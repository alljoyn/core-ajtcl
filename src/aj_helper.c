/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include "aj_helper.h"
#include "alljoyn.h"

#include "aj_link_timeout.h"

#define UNMARSHAL_TIMEOUT (100 * 1000)
#define CONNECT_TIMEOUT   (60 * 1000)
#define CONNECT_PAUSE     (10 * 1000)

#define MAX_TIMERS 4

/**
 *  Type to describe pending timers
 */
typedef struct {
    TimeoutHandler handler; /**< The callback handler */
    void* context;          /**< A context pointer passed in by the user */
    uint32_t abs_time;      /**< The absolute time when this timer will fire */
    uint32_t repeat;        /**< The amount of time between timer events */
} Timer;

static Timer Timers[MAX_TIMERS] = {
    { NULL }
};

static uint32_t RunExpiredTimers(uint32_t now)
{
    uint32_t i = 0;
    uint32_t next = (uint32_t) -1;

    for (; i < MAX_TIMERS; ++i) {
        Timer* timer = Timers + i;
        if (timer->handler != NULL && timer->abs_time <= now) {
            (timer->handler)(timer->context);

            if (timer->repeat) {
                timer->abs_time += timer->repeat;
            } else {
                memset(timer, 0, sizeof(Timer));
            }
        }

        // track the next time we need to run
        if (timer->handler != NULL && next > timer->abs_time) {
            next = timer->abs_time;
        }
    }

    // return the next timeout that will run
    return next;
}

uint32_t AJ_SetTimer(uint32_t relative_time, TimeoutHandler handler, void* context, uint32_t repeat)
{
    uint32_t i;
    for (i = 0; i < MAX_TIMERS; ++i) {
        Timer* timer = Timers + i;
        // need to find an available timer slot
        if (timer->handler == NULL) {
            AJ_Time start = { 0, 0 };
            uint32_t now = AJ_GetElapsedTime(&start, FALSE);
            timer->handler = handler;
            timer->context = context;
            timer->repeat = repeat;
            timer->abs_time = now + relative_time;
            return i + 1;
        }
    }

    // available slot not found!
    return 0;
}

void AJ_CancelTimer(uint32_t id)
{
    Timer* timer = Timers + (id - 1);
    AJ_ASSERT(id > 0 && id <= MAX_TIMERS);
    memset(timer, 0, sizeof(Timer));
}


AJ_Status AJ_RunAllJoynService(AJ_BusAttachment* bus, AllJoynConfiguration* config)
{
    uint8_t connected = FALSE;
    AJ_Status status = AJ_OK;

    while (TRUE) {
        AJ_Time start = { 0, 0 };
        AJ_Message msg;
        uint32_t now;
        // get the next timeout
        //Timer* timer = GetNextTimeout();
        uint32_t next;
        // wait forever
        uint32_t timeout = (uint32_t) -1;

        if (!connected) {
            status = AJ_StartService2(
                bus,
                config->daemonName, config->connect_timeout, config->connected,
                config->session_port, config->service_name, config->flags, config->opts);
            if (status != AJ_OK) {
                continue;
            }
            AJ_InfoPrintf(("StartService returned AJ_OK\n"));
            AJ_InfoPrintf(("Connected to Daemon:%s\n", AJ_GetUniqueName(bus)));

            connected = TRUE;

            /* Register a callback for providing bus authentication password */
            AJ_BusSetPasswordCallback(bus, config->password_callback);

            /* Configure timeout for the link to the daemon bus */
            AJ_SetBusLinkTimeout(bus, config->link_timeout);

            if (config->connection_handler != NULL) {
                (config->connection_handler)(connected);
            }
        }

        // absolute time in milliseconds
        now = AJ_GetElapsedTime(&start, FALSE);
        next = RunExpiredTimers(now);

        if (next != (uint32_t) -1) {
            // if no timers running, wait forever
            timeout = next;
        }

        status = AJ_UnmarshalMsg(bus, &msg, min(500, timeout));
        if (AJ_ERR_TIMEOUT == status && AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(bus)) {
            status = AJ_ERR_READ;
        }

        if (status == AJ_ERR_TIMEOUT) {
            // go back around and handle the expired timers
            continue;
        }

        if (status == AJ_OK) {
            uint8_t handled = FALSE;
            const MessageHandlerEntry* message_entry = config->message_handlers;
            const PropHandlerEntry* prop_entry = config->prop_handlers;

            // check the user's handlers first.  ANY message that AllJoyn can handle is override-able.
            while (handled != TRUE && message_entry->msgid != 0) {
                if (message_entry->msgid == msg.msgId) {
                    if (msg.hdr->msgType == AJ_MSG_METHOD_CALL) {
                        // build a method reply
                        AJ_Message reply;
                        status = AJ_MarshalReplyMsg(&msg, &reply);

                        if (status == AJ_OK) {
                            status = (message_entry->handler)(&msg, &reply);
                        }

                        if (status == AJ_OK) {
                            status = AJ_DeliverMsg(&reply);
                        }
                    } else {
                        // call the handler!
                        status = (message_entry->handler)(&msg, NULL);
                    }

                    handled = TRUE;
                }

                ++message_entry;
            }

            // we need to check whether this is a property getter or setter.
            // these are stored in an array because multiple getters and setters can exist if running more than one bus object
            while (handled != TRUE && prop_entry->msgid != 0) {
                if (prop_entry->msgid == msg.msgId) {
                    // extract the method from the ID; GetProperty or SetProperty
                    uint32_t method = prop_entry->msgid & 0x000000FF;
                    if (method == AJ_PROP_GET) {
                        status = AJ_BusPropGet(&msg, prop_entry->callback, prop_entry->context);
                    } else if (method == AJ_PROP_SET) {
                        status = AJ_BusPropSet(&msg, prop_entry->callback, prop_entry->context);
                    } else {
                        // this should never happen!!!
                        AJ_ASSERT(!"Invalid property method");
                    }

                    handled = TRUE;
                }

                ++prop_entry;
            }

            // handler not found!
            if (handled == FALSE) {
                if (msg.msgId == AJ_METHOD_ACCEPT_SESSION) {
                    uint8_t accepted = (config->acceptor)(&msg);
                    status = AJ_BusReplyAcceptSession(&msg, accepted);
                } else {
                    status = AJ_BusHandleBusMessage(&msg);
                }
            }

            // Any received packets indicates the link is active, so call to reinforce the bus link state
            AJ_NotifyLinkActive();
        }
        /*
         * Unarshaled messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if (status == AJ_ERR_READ) {
            AJ_InfoPrintf(("AllJoyn disconnect\n"));
            AJ_InfoPrintf(("Disconnected from Daemon:%s\n", AJ_GetUniqueName(bus)));
            AJ_Disconnect(bus);
            connected = FALSE;
            if (config->connection_handler != NULL) {
                (config->connection_handler)(connected);
            }
            /*
             * Sleep a little while before trying to reconnect
             */
            AJ_Sleep(10 * 1000);
        }
    }

    // this will never actually return!
    return AJ_OK;
}


AJ_Status AJ_StartService(AJ_BusAttachment* bus,
                          const char* daemonName,
                          uint32_t timeout,
                          uint16_t port,
                          const char* name,
                          uint32_t flags,
                          const AJ_SessionOpts* opts
                          )
{
    return AJ_StartService2(bus, daemonName, timeout, FALSE, port, name, flags, opts);
}

AJ_Status AJ_StartService2(AJ_BusAttachment* bus,
                           const char* daemonName,
                           uint32_t timeout,
                           uint8_t connected,
                           uint16_t port,
                           const char* name,
                           uint32_t flags,
                           const AJ_SessionOpts* opts
                           )
{
    AJ_Status status;
    AJ_Time timer;
    uint8_t serviceStarted = FALSE;
    uint8_t initial = TRUE;
    AJ_InitTimer(&timer);

    while (TRUE) {
        if (AJ_GetElapsedTime(&timer, TRUE) > timeout) {
            return AJ_ERR_TIMEOUT;
        }
        if (!initial || !connected) {
            initial = FALSE;
            AJ_InfoPrintf(("Attempting to connect to bus\n"));
            status = AJ_Connect(bus, daemonName, CONNECT_TIMEOUT);
            if (status != AJ_OK) {
                AJ_WarnPrintf(("Failed to connect to bus sleeping for %d seconds\n", CONNECT_PAUSE / 1000));
                AJ_Sleep(CONNECT_PAUSE);
                continue;
            }
            AJ_InfoPrintf(("AllJoyn service connected to bus\n"));
        }
        /*
         * Kick things off by binding a session port
         */
        status = AJ_BusBindSessionPort(bus, port, opts);
        if (status == AJ_OK) {
            break;
        }
        AJ_ErrPrintf(("Failed to send bind session port message\n"));
        AJ_Disconnect(bus);
    }

    while (!serviceStarted && (status == AJ_OK)) {
        AJ_Message msg;

        AJ_GetElapsedTime(&timer, TRUE);

        status = AJ_UnmarshalMsg(bus, &msg, UNMARSHAL_TIMEOUT);

        /*
         * TODO This is a temporary hack to work around buggy select imlpementations
         */
        if (status == AJ_ERR_TIMEOUT) {
            if (AJ_GetElapsedTime(&timer, TRUE) < UNMARSHAL_TIMEOUT) {
                AJ_WarnPrintf(("Spurious timeout error - continuing\n"));
                status = AJ_OK;
                continue;
            }
        }

        if (status != AJ_OK) {
            break;
        }

        switch (msg.msgId) {
        case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
            if (msg.hdr->msgType == AJ_MSG_ERROR) {
                status = AJ_ERR_FAILURE;
            } else {
                status = AJ_BusRequestName(bus, name, flags);
            }
            break;

        case AJ_REPLY_ID(AJ_METHOD_REQUEST_NAME):
            if (msg.hdr->msgType == AJ_MSG_ERROR) {
                status = AJ_ERR_FAILURE;
            } else {
                status = AJ_BusAdvertiseName(bus, name, AJ_TRANSPORT_ANY, AJ_BUS_START_ADVERTISING);
            }
            break;

        case AJ_REPLY_ID(AJ_METHOD_ADVERTISE_NAME):
            if (msg.hdr->msgType == AJ_MSG_ERROR) {
                status = AJ_ERR_FAILURE;
            } else {
                serviceStarted = TRUE;
            }
            break;

        default:
            /*
             * Pass to the built-in bus message handlers
             */
            status = AJ_BusHandleBusMessage(&msg);
            break;
        }
        AJ_CloseMsg(&msg);
    }

    if (status != AJ_OK) {
        AJ_WarnPrintf(("AllJoyn disconnect bus status=%s\n", AJ_StatusText(status)));
        AJ_Disconnect(bus);
    }
    return status;
}

AJ_Status AJ_StartClient(AJ_BusAttachment* bus,
                         const char* daemonName,
                         uint32_t timeout,
                         const char* name,
                         uint16_t port,
                         uint32_t* sessionId,
                         const AJ_SessionOpts* opts
                         )
{
    return AJ_StartClient2(bus, daemonName, timeout, FALSE, name, port, sessionId, opts);
}

AJ_Status AJ_StartClient2(AJ_BusAttachment* bus,
                          const char* daemonName,
                          uint32_t timeout,
                          uint8_t connected,
                          const char* name,
                          uint16_t port,
                          uint32_t* sessionId,
                          const AJ_SessionOpts* opts
                          )
{
    AJ_Status status = AJ_OK;
    AJ_Time timer;
    AJ_Time unmarshalTimer;
    uint8_t foundName = FALSE;
    uint8_t clientStarted = FALSE;
    uint8_t initial = TRUE;
    AJ_InitTimer(&timer);

    while (TRUE) {
        if (AJ_GetElapsedTime(&timer, TRUE) > timeout) {
            return AJ_ERR_TIMEOUT;
        }
        if (!initial || !connected) {
            initial = FALSE;
            AJ_InfoPrintf(("Attempting to connect to bus\n"));
            status = AJ_Connect(bus, daemonName, CONNECT_TIMEOUT);
            if (status != AJ_OK) {
                AJ_WarnPrintf(("Failed to connect to bus sleeping for %d seconds\n", CONNECT_PAUSE / 1000));
                AJ_Sleep(CONNECT_PAUSE);
                continue;
            }
            AJ_InfoPrintf(("AllJoyn client connected to bus\n"));
        }
        /*
         * Kick things off by finding the service names
         */
        status = AJ_BusFindAdvertisedName(bus, name, AJ_BUS_START_FINDING);
        if (status == AJ_OK) {
            break;
        }
        AJ_WarnPrintf(("FindAdvertisedName failed\n"));
        AJ_Disconnect(bus);
    }

    *sessionId = 0;

    while (!clientStarted && (status == AJ_OK)) {
        AJ_Message msg;

        if (AJ_GetElapsedTime(&timer, TRUE) > timeout) {
            return AJ_ERR_TIMEOUT;
        }
        status = AJ_UnmarshalMsg(bus, &msg, UNMARSHAL_TIMEOUT);
        /*
         * TODO This is a temporary hack to work around buggy select imlpementations
         */
        AJ_InitTimer(&unmarshalTimer);
        if (status == AJ_ERR_TIMEOUT && (AJ_GetElapsedTime(&unmarshalTimer, TRUE) < UNMARSHAL_TIMEOUT || !foundName)) {
            /*
             * Timeouts are expected until we find a name
             */
            status = AJ_OK;
            continue;
        }

        if (status != AJ_OK) {
            break;
        }
        switch (msg.msgId) {

        case AJ_REPLY_ID(AJ_METHOD_FIND_NAME):
        case AJ_REPLY_ID(AJ_METHOD_FIND_NAME_BY_TRANSPORT):
            if (msg.hdr->msgType == AJ_MSG_ERROR) {
                status = AJ_ERR_FAILURE;
            } else {
                uint32_t disposition;
                AJ_UnmarshalArgs(&msg, "u", &disposition);
                if ((disposition != AJ_FIND_NAME_STARTED) && (disposition != AJ_FIND_NAME_ALREADY)) {
                    status = AJ_ERR_FAILURE;
                }
            }
            break;


        case AJ_SIGNAL_FOUND_ADV_NAME:
            {
                AJ_Arg arg;
                AJ_UnmarshalArg(&msg, &arg);
                AJ_InfoPrintf(("FoundAdvertisedName(%s)\n", arg.val.v_string));
                foundName = TRUE;
                status = AJ_BusJoinSession(bus, arg.val.v_string, port, opts);
            }
            break;

        case AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION):
            {
                uint32_t replyCode;

                if (msg.hdr->msgType == AJ_MSG_ERROR) {
                    status = AJ_ERR_FAILURE;
                } else {
                    status = AJ_UnmarshalArgs(&msg, "uu", &replyCode, sessionId);
                    if (replyCode == AJ_JOINSESSION_REPLY_SUCCESS) {
                        clientStarted = TRUE;
                    } else {
                        status = AJ_ERR_FAILURE;
                    }
                }
            }
            break;

        case AJ_SIGNAL_SESSION_LOST:
            /*
             * Force a disconnect
             */
            status = AJ_ERR_READ;
            break;

        default:
            /*
             * Pass to the built-in bus message handlers
             */
            status = AJ_BusHandleBusMessage(&msg);
            break;
        }
        AJ_CloseMsg(&msg);
    }
    if (status != AJ_OK) {
        AJ_WarnPrintf(("AllJoyn disconnect bus status=%s\n", AJ_StatusText(status)));
        AJ_Disconnect(bus);
    }
    return status;
}
