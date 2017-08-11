/**
 * @file
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#define AJ_MODULE BASIC_SERVICE

#include <signal.h>
#include <stdio.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>

#define CONNECT_ATTEMPTS   10
static const char s_serviceName[] = "org.alljoyn.Bus.sample";
static const char s_servicePath[] = "/sample";
static const uint16_t s_servicePort = 25;
static AJ_BusAttachment s_bus;
static uint8_t s_connected = FALSE;

uint8_t dbgBASIC_SERVICE = 0;
/**
 * The interface name followed by the method signatures.
 *
 * See also .\inc\aj_introspect.h
 */
static const char* const s_sampleInterface[] = {
    "org.alljoyn.Bus.sample",   /* The first entry is the interface name. */
    "?Dummy foo<i",             /* This is just a dummy entry at index 0 for illustration purposes. */
    "?cat inStr1<s inStr2<s outStr>s", /* Method at index 1. */
    NULL
};

/**
 * A NULL terminated collection of all interfaces.
 */
static const AJ_InterfaceDescription s_sampleInterfaces[] = {
    s_sampleInterface,
    NULL
};

/**
 * Objects implemented by the application. The first member in the AJ_Object structure is the path.
 * The second is the collection of all interfaces at that path.
 */
static const AJ_Object s_appObjects[] = {
    { s_servicePath, s_sampleInterfaces },
    { NULL }
};

/*
 * The value of the arguments are the indices of the
 * object path in s_appObjects (above), interface in s_sampleInterfaces (above), and
 * member indices in the interface.
 * The 'cat' index is 1 because the first entry in s_sampleInterface is the interface name.
 * This makes the first index (index 0 of the methods) the second string in
 * s_sampleInterface[] which, for illustration purposes is a dummy entry.
 * The index of the method we implement for basic_service, 'cat', is 1 which is the third string
 * in the array of strings s_sampleInterface[].
 *
 * See also .\inc\aj_introspect.h
 */
#define BASIC_SERVICE_CAT AJ_APP_MESSAGE_ID(0, 0, 1)

/*
 * Use async version of API for reply
 */
static uint8_t asyncForm = TRUE;

static AJ_Status AppHandleCat(AJ_Message* msg)
{
    const char* string0;
    const char* string1;
    char buffer[256];
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "ss", &string0, &string1);

    /* We have the arguments. Now do the concatenation. */
    strncpy(buffer, string0, ArraySize(buffer));
    buffer[ArraySize(buffer) - 1] = '\0';
    strncat(buffer, string1, ArraySize(buffer) - strlen(buffer) - 1);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_STRING, 0, buffer, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

/* All times are expressed in milliseconds. */
#define CONNECT_TIMEOUT     (1000 * 60)
#define SLEEP_TIME          (1000 * 2)

/* SIGINT signal handler. */
static void SigIntHandler(int sig)
{
    AJ_UNUSED(sig);
    if (s_connected) {
        AJ_Disconnect(&s_bus);
    }
    AJ_AlwaysPrintf(("\nbasic_service exiting after SIGINT (OK)\n"));
    exit(0);
}

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    uint32_t sessionId = 0;

    /* Install SIGINT handler. */
    signal(SIGINT, SigIntHandler);

    /* One time initialization before calling any other AllJoyn APIs. */
    AJ_Initialize();

    /* This is for debug purposes and is optional. */
    AJ_PrintXML(s_appObjects);

    AJ_RegisterObjects(s_appObjects, NULL);

    while (TRUE) {
        AJ_Message msg;

        if (!s_connected) {
            status = AJ_StartService(&s_bus,
                                     NULL,
                                     CONNECT_TIMEOUT,
                                     FALSE,
                                     s_servicePort,
                                     s_serviceName,
                                     AJ_NAME_REQ_DO_NOT_QUEUE,
                                     NULL);

            if (status != AJ_OK) {
                continue;
            }

            AJ_InfoPrintf(("StartService returned %d, session_id=%u\n", status, sessionId));
            s_connected = TRUE;
        }

        status = AJ_UnmarshalMsg(&s_bus, &msg, AJ_UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    status = AJ_BusReplyAcceptSession(&msg, TRUE);
                    AJ_InfoPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
                }
                break;

            case BASIC_SERVICE_CAT:
                status = AppHandleCat(&msg);
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u\n", id, reason));
                }
                break;

            default:
                /* Pass to the built-in handlers. */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }

        /* Messages MUST be discarded to free resources. */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_READ) || (status == AJ_ERR_WRITE)) {
            AJ_AlwaysPrintf(("AllJoyn disconnect.\n"));
            AJ_Disconnect(&s_bus);
            s_connected = FALSE;

            /* Sleep a little while before trying to reconnect. */
            AJ_Sleep(SLEEP_TIME);
        }
    }

    AJ_AlwaysPrintf(("Basic service exiting with status %d.\n", status));

    return status;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
