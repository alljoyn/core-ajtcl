/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2013-2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <alljoyn.h>

#define CONNECT_TIMEOUT    (1000ul * 60)
#define CONNECT_PAUSE      (1000ul * 10)
#define UNMARSHAL_TIMEOUT  (1000ul * 5)
#define METHOD_TIMEOUT     (1000ul * 3)

/// globals
AJ_Status status = AJ_OK;
AJ_BusAttachment bus;
uint8_t connected = FALSE;
uint32_t g_sessionId = 0ul;
AJ_Status authStatus = AJ_ERR_NULL;
uint32_t sendTTL = 0;

static const char ServiceName[] = "org.alljoyn.bus.test.sessions";
static const uint16_t ServicePort = 25;
static uint32_t authenticate = TRUE;

static const char* const testInterface[] = {
    "org.alljoyn.bus.test.sessions",
    "!Chat >s",
    NULL
};


static const AJ_InterfaceDescription testInterfaces[] = {
    testInterface,
    NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object AppObjects[] = {
    { "/sessions", testInterfaces },
    { NULL }
};

#define APP_CHAT_SIGNAL  AJ_APP_MESSAGE_ID(0, 0, 0)


/*
 * Let the application do some work
 */
void AppDoWork()
{
    AJ_Printf("AppDoWork\n");
}


static const char PWD[] = "1234";

static uint32_t PasswordCallback(uint8_t* buffer, uint32_t bufLen)
{
    memcpy(buffer, PWD, sizeof(PWD));
    return sizeof(PWD) - 1;
}

void AuthCallback(const void* context, AJ_Status status)
{
    *((AJ_Status*)context) = status;
}

AJ_Status AppSendChatSignal(AJ_BusAttachment* bus, uint32_t sessionId, const char* chatString, uint8_t flags, uint32_t ttl)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;

    status = AJ_MarshalSignal(bus, &msg, APP_CHAT_SIGNAL, NULL, sessionId, flags, ttl);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", chatString);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    AJ_Printf("TX chat: %s\n", chatString);
    return status;
}

AJ_Status AppHandleChatSignal(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    char* chatString;

    AJ_UnmarshalArgs(msg, "s", &chatString);
    AJ_Printf("RX chat from %s[%u]: %s\n", msg->sender, msg->sessionId, chatString);
    return status;
}

void Do_Connect()
{
    while (!connected) {
        AJ_Status status;
        AJ_Printf("Attempting to connect to bus\n");
        status = AJ_FindBusAndConnect(&bus, NULL, CONNECT_TIMEOUT);
        if (status != AJ_OK) {
            AJ_Printf("Failed to connect to bus sleeping for %lu seconds\n", CONNECT_PAUSE / 1000);
            AJ_Sleep(CONNECT_PAUSE);
            continue;
        }
        connected = TRUE;
        AJ_Printf("AllJoyn service connected to bus\n");
        AJ_Printf("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus));
        AJ_BusSetSignalRule(&bus, "type='signal',member='NameOwnerChanged',interface='org.freedesktop.DBus'", AJ_BUS_SIGNAL_ALLOW);
    }
}

int AJ_Main()
{
    AJ_Initialize();
    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);

    Do_Connect();

    if (authenticate) {
        AJ_BusSetPasswordCallback(&bus, PasswordCallback);
    } else {
        authStatus = AJ_OK;
    }

    AJ_StartReadFromStdIn();
    while (TRUE) {
        // check for serial input and dispatch if needed.
        char buf[1024];
        AJ_Message msg;
        // read a line
        if (AJ_GetCmdLine(buf, 1024) != NULL && strlen(buf) > 0) {
            char*command;
            AJ_Printf(">~~~%s\n", buf);
            command = strtok(buf, " \r\n");
            if (!command) {
                continue;
            }
            if (0 == strcmp("startservice", command)) {
                uint16_t port = 0;
                const char* name;
                AJ_SessionOpts opts;
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    name = token;
                } else {
                    name = ServiceName;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    port = (uint16_t)atoi(token);
                }
                if (port == 0) {
                    port = ServicePort;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.isMultipoint = (0 == strcmp("true", token));
                } else {
                    opts.isMultipoint = 0;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.traffic = atoi(token);
                } else {
                    opts.traffic = 0x1;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.proximity = atoi(token);
                } else {
                    opts.proximity = 0xFF;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.transports = atoi(token);
                } else {
                    opts.transports = 0xFFFF;
                }

                status = AJ_StartService(&bus, NULL, CONNECT_TIMEOUT, TRUE, port, name, AJ_NAME_REQ_DO_NOT_QUEUE, &opts);
            } else if (0 == strcmp("find", command)) {
                char* namePrefix = strtok(NULL, " \r\n");
                if (!namePrefix) {
                    AJ_Printf("Usage: find <name_prefix>\n");
                    continue;
                }
                status = AJ_BusFindAdvertisedName(&bus, namePrefix, AJ_BUS_START_FINDING);
            } else if (0 == strcmp("cancelfind", command)) {
                char* namePrefix = strtok(NULL, " \r\n");
                if (!namePrefix) {
                    AJ_Printf("Usage: cancelfind <name_prefix>\n");
                    continue;
                }
                status = AJ_BusFindAdvertisedName(&bus, namePrefix, AJ_BUS_STOP_FINDING);
            } else if (0 == strcmp("find2", command)) {
                char* namePrefix = strtok(NULL, " \r\n");
                uint16_t transport = 0;
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    transport = (uint16_t)atoi(token);
                }
                if (!namePrefix || !transport) {
                    AJ_Printf("Usage: find2 <name_prefix> <transport>\n");
                    continue;
                }
                status = AJ_BusFindAdvertisedNameByTransport(&bus, namePrefix, transport, AJ_BUS_START_FINDING);
            } else if (0 == strcmp("cancelfind2", command)) {
                char* namePrefix = strtok(NULL, " \r\n");
                uint16_t transport = 0;
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    transport = (uint16_t)atoi(token);
                }
                if (!namePrefix || !transport) {
                    AJ_Printf("Usage: cancelfind2 <name_prefix> <transport>\n");
                    continue;
                }
                status = AJ_BusFindAdvertisedNameByTransport(&bus, namePrefix, transport, AJ_BUS_STOP_FINDING);
            } else if (0 == strcmp("requestname", command)) {
                char* name = strtok(NULL, " \r\n");
                if (!name) {
                    AJ_Printf("Usage: requestname <name>\n");
                    continue;
                }
                status = AJ_BusRequestName(&bus, name, AJ_NAME_REQ_DO_NOT_QUEUE);
            } else if (0 == strcmp("releasename", command)) {
                char* name = strtok(NULL, " \r\n");
                if (!name) {
                    AJ_Printf("Usage: releasename <name>\n");
                    continue;
                }
                status = AJ_BusReleaseName(&bus, name);
            } else if (0 == strcmp("advertise", command)) {
                uint16_t transport = 0xFFFF;
                char* token = NULL;
                char* name = strtok(NULL, " \r\n");
                if (!name) {
                    AJ_Printf("Usage: advertise <name> [transports]\n");
                    continue;
                }
                token = strtok(NULL, " \r\n");

                if (token) {
                    transport = (uint16_t)atoi(token);
                }
                status = AJ_BusAdvertiseName(&bus, name, transport, AJ_BUS_START_ADVERTISING, 0);

            } else if (0 == strcmp("canceladvertise", command)) {
                uint16_t transport = 0xFFFF;
                char* token = NULL;
                char* name = strtok(NULL, " \r\n");
                if (!name) {
                    AJ_Printf("Usage: canceladvertise <name> [transports]\n");
                    continue;
                }
                token = strtok(NULL, " \r\n");

                if (token) {
                    transport = (uint16_t)atoi(token);
                }
                status = AJ_BusAdvertiseName(&bus, name, transport, AJ_BUS_STOP_ADVERTISING, 0);

            } else if (0 == strcmp("bind", command)) {
                AJ_SessionOpts opts;
                uint16_t port = 0;
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    port = (uint16_t)atoi(token);
                }
                if (port == 0) {
                    AJ_Printf("Usage: bind <port> [isMultipoint] [traffic] [proximity] [transports]\n");
                    continue;
                }
                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.isMultipoint = (0 == strcmp("true", token));
                } else {
                    opts.isMultipoint = 0;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.traffic = atoi(token);
                } else {
                    opts.traffic = 0x1;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.proximity = atoi(token);
                } else {
                    opts.proximity = 0xFF;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.transports = atoi(token);
                } else {
                    opts.transports = 0xFFFF;
                }

                status = AJ_BusBindSessionPort(&bus, port, &opts, 0);
            } else if (0 == strcmp("unbind", command)) {
                uint16_t port = 0;
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    port = (uint16_t) atoi(token);
                }

                if (port == 0) {
                    AJ_Printf("Usage: unbind <port>\n");
                    continue;
                }
                status = AJ_BusUnbindSession(&bus, port);
            } else if (0 == strcmp("join", command)) {
                AJ_SessionOpts opts;
                uint16_t port = 0;
                char* name = strtok(NULL, " \r\n");
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    port = (uint16_t)atoi(token);
                } else {
                    port = 0;
                }
                if (!name || (port == 0)) {
                    AJ_Printf("Usage: join <name> <port> [isMultipoint] [traffic] [proximity] [transports]\n");
                    continue;
                }
                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.isMultipoint = (0 == strcmp("true", token));
                } else {
                    opts.isMultipoint = 0;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.traffic = (uint8_t)atoi(token);
                } else {
                    opts.traffic = 0x1;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.proximity = (uint8_t)atoi(token);
                } else {
                    opts.proximity = 0xFF;
                }

                token = strtok(NULL, " \r\n");
                if (token) {
                    opts.transports = (uint16_t)atoi(token);
                } else {
                    opts.transports = 0xFFFF;
                }

                status = AJ_BusJoinSession(&bus, name, port, &opts);
            } else if (0 == strcmp("leave", command)) {
                char* sessionIdStr = strtok(NULL, "\r\n");
                uint32_t sessionId = 0;
                if (sessionIdStr) {
                    sessionId = (uint32_t)atoi(sessionIdStr);
                }
                if (sessionId == 0) {
                    AJ_Printf("Usage: leave <sessionId>\n");
                    continue;
                }
                status = AJ_BusLeaveSession(&bus, sessionId);
            } else if (0 == strcmp("addmatch", command)) {
                char* ruleString = strtok(NULL, "\r\n");
                if (!ruleString) {
                    AJ_Printf("Usage: addmatch <rule>\n");
                    continue;
                }
                status = AJ_BusSetSignalRule(&bus, ruleString, AJ_BUS_SIGNAL_ALLOW);
            } else if (0 == strcmp("removematch", command)) {
                char* ruleString = strtok(NULL, "\r\n");
                if (!ruleString) {
                    AJ_Printf("Usage: removematch <rule>\n");
                    continue;
                }
                status = AJ_BusSetSignalRule(&bus, ruleString, AJ_BUS_SIGNAL_DENY);
            }  else if (0 == strcmp("sendttl", command)) {
                int32_t ttl = 0;
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    ttl = atoi(token);
                }
                if (ttl < 0) {
                    AJ_Printf("Usage: sendttl <ttl>\n");
                    continue;
                }
                sendTTL = ttl;
            } else if (0 == strcmp("schat", command)) {
                char* chatMsg = strtok(NULL, "\r\n");
                if (!chatMsg) {
                    AJ_Printf("Usage: schat <msg>\n");
                    continue;
                }
                status = AppSendChatSignal(&bus, 0, chatMsg, ALLJOYN_FLAG_SESSIONLESS, sendTTL);
            } else if (0 == strcmp("chat", command)) {
                char* sessionIdString = strtok(NULL, " \r\n");
                char*chatMsg;

                uint32_t session = g_sessionId;
                if (sessionIdString != NULL) {
                    if (sessionIdString[0] != '#') {
                        session = atol(sessionIdString);
                    }
                }

                chatMsg = strtok(NULL, "\r\n");
                if (chatMsg) {
                    status = AppSendChatSignal(&bus, session, chatMsg, 0, sendTTL);
                }
            } else if (0 == strcmp("cancelsessionless", command)) {
                uint32_t serialId = 0;
                char* token = strtok(NULL, " \r\n");
                if (token) {
                    serialId = (uint32_t)atoi(token);
                }
                if (serialId == 0) {
                    AJ_Printf("Invalid serial number\n");
                    AJ_Printf("Usage: cancelsessionless <serialNum>\n");
                    continue;
                }
                status = AJ_BusCancelSessionless(&bus, serialId);
            } else if (0 == strcmp("exit", command)) {
                break;
            } else if (0 == strcmp("help", command)) {
                //AJ_Printf("debug <module_name> <level>                                   - Set debug level for a module\n");
                AJ_Printf("startservice [name] [port] [isMultipoint] [traffic] [proximity] [transports] - Startservice\n");
                AJ_Printf("requestname <name>                                            - Request a well-known name\n");
                AJ_Printf("releasename <name>                                            - Release a well-known name\n");
                AJ_Printf("bind <port> [isMultipoint] [traffic] [proximity] [transports] - Bind a session port\n");
                AJ_Printf("unbind <port>                                                 - Unbind a session port\n");
                AJ_Printf("advertise <name> [transports]                                 - Advertise a name\n");
                AJ_Printf("canceladvertise <name> [transports]                           - Cancel an advertisement\n");
                AJ_Printf("find <name_prefix>                                            - Discover names that begin with prefix\n");
                AJ_Printf("find2 <name_prefix> <transport>                               - Discover names that begin with prefix by specific transports\n");
                AJ_Printf("cancelfind <name_prefix>                                      - Cancel discovering names that begins with prefix\n");
                AJ_Printf("cancelfind2 <name_prefix> <transport>                         - Cancel discovering names that begins with prefix by specific transports\n");
                AJ_Printf("join <name> <port> [isMultipoint] [traffic] [proximity] [transports] - Join a session\n");
                AJ_Printf("leave <sessionId>                                             - Leave a session\n");
                AJ_Printf("chat <sessionId> <msg>                                        - Send a message over a given session\n");
                AJ_Printf("schat <msg>                                                   - Send a sessionless message\n");
                AJ_Printf("cancelsessionless <serialNum>                                 - Cancel a sessionless message\n");
                AJ_Printf("addmatch <rule>                                               - Add a DBUS rule\n");
                AJ_Printf("removematch <rule>                                            - Remove a DBUS rule\n");
                AJ_Printf("sendttl <ttl>                                                 - Set default ttl (in ms) for all chat messages (0 = infinite)\n");
                AJ_Printf("exit                                                          - Exit this program\n");
                AJ_Printf("\n");
                continue;
            } else {
                AJ_Printf("Unknown command: %s\n", command);
                continue;
            }
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                AppDoWork();
                continue;
            }
        }

        if (status == AJ_OK) {
            switch (msg.msgId) {

            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    AJ_Printf("Accepting...\n");
                    AJ_UnmarshalArgs(&msg, "qus", &port, &g_sessionId, &joiner);
                    status = AJ_BusReplyAcceptSession(&msg, TRUE);
                    if (status == AJ_OK) {
                        AJ_Printf("Accepted session session_id=%u joiner=%s\n", g_sessionId, joiner);
                    } else {
                        AJ_Printf("AJ_BusReplyAcceptSession: error %d\n", status);
                    }
                }
                break;

            case AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION):
                {
                    uint32_t replyCode;

                    if (msg.hdr->msgType == AJ_MSG_ERROR) {
                        status = AJ_ERR_FAILURE;
                    } else {
                        status = AJ_UnmarshalArgs(&msg, "uu", &replyCode, &g_sessionId);
                        if (replyCode == AJ_JOINSESSION_REPLY_SUCCESS) {
                            AJ_Printf("Joined session session_id=%u\n", g_sessionId);
                        } else {
                            AJ_Printf("Joine session failed\n");
                        }
                    }
                }
                break;

            case APP_CHAT_SIGNAL:
                status = AppHandleChatSignal(&msg);
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /*
                 * don't force a disconnect, be ready to accept another session
                 */
                break;

            default:
                /*
                 * Pass to the built-in handlers
                 */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }
        /*
         * Messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_SESSION_LOST) || (status == AJ_ERR_READ) || (status == AJ_ERR_LINK_DEAD)) {
            AJ_Printf("AllJoyn disconnect\n");
            AJ_Printf("Disconnected from Daemon:%s\n", AJ_GetUniqueName(&bus));
            AJ_Disconnect(&bus);
            connected = FALSE;
            /*
             * Sleep a little while before trying to reconnect
             */
            AJ_Sleep(10 * 1000);
            Do_Connect();
        }
    }

    AJ_StopReadFromStdIn();
    return 0;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
