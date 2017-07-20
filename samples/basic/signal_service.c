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
#define AJ_MODULE SIGNAL_SERVICE

#include <signal.h>
#include <stdio.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_msg.h>

uint8_t dbgSIGNAL_SERVICE = 0;
/**
 * Statics.
 */
static AJ_BusAttachment s_busAttachment;
static char s_propertyName[128] = "Default name";
static uint8_t s_connected = FALSE;

/**
 * Static constants.
 */
static const size_t s_propertyNameSize = sizeof(s_propertyName) / sizeof(s_propertyName[0]);
static const char s_interfaceName[] = "org.alljoyn.Bus.signal_sample";
static const char s_serviceName[] = "org.alljoyn.Bus.signal_sample";
static const char s_servicePath[] = "/";
static const uint16_t s_servicePort = 25;

/**
 * The interface name followed by the method signatures.
 *
 * See also .\inc\aj_introspect.h
 */
static const char* const s_sampleInterface[] = {
    s_interfaceName,              /* The first entry is the interface name. */
    "!nameChanged newName>s",   /* Signal at index 0 with an output string of the new name. */
    "@name=s",                  /* Read/write property of the name. */
    NULL
};

/**
 * A NULL terminated collection of all interfaces.
 */
static const AJ_InterfaceDescription s_sampleInterfaces[] = {
    AJ_PropertiesIface,     /* This must be included for any interface that has properties. */
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
 * The 'nameChanged' index is 0 because the first entry in s_sampleInterface is the interface name.
 * This makes the first index (index 0 of the methods) the second string in
 * s_sampleInterface[].
 *
 * See also .\inc\aj_introspect.h
 */
#define BASIC_SIGNAL_SERVICE_SIGNAL     AJ_APP_MESSAGE_ID(0, 1, 0)
#define BASIC_SIGNAL_SERVICE_GET_NAME   AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define BASIC_SIGNAL_SERVICE_SET_NAME   AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)

/*
 * Property identifiers for the properies this application implements
 * Encode a property id from the object path, interface, and member indices.
 */
#define BASIC_SIGNAL_SERVICE_NAME_ID    AJ_APP_PROPERTY_ID(0, 1, 1)

static AJ_Status SendSignal()
{
    AJ_Message msg;

    AJ_AlwaysPrintf(("Emitting Name Changed Signal. New value for property 'name' is '%s'.\n", s_propertyName));

    /* For the signal to transmit outside of the current process the session ID must be 0. */
    AJ_MarshalSignal(&s_busAttachment, &msg, BASIC_SIGNAL_SERVICE_SIGNAL, NULL, 0, AJ_FLAG_GLOBAL_BROADCAST, 0);
    AJ_MarshalArgs(&msg, "s", s_propertyName);

    return AJ_DeliverMsg(&msg);
}

static AJ_Status GetName(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;

    if (propId == BASIC_SIGNAL_SERVICE_NAME_ID) {
        status = AJ_MarshalArgs(replyMsg, "s", s_propertyName);
    }

    return status;
}

static AJ_Status SetName(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;

    if (propId == BASIC_SIGNAL_SERVICE_NAME_ID) {
        char*string;
        AJ_UnmarshalArgs(replyMsg, "s", &string);
        strncpy(s_propertyName, string, s_propertyNameSize);
        s_propertyName[s_propertyNameSize - 1] = '\0';
        AJ_AlwaysPrintf(("Set 'name' property was called changing name to '%s'.\n", s_propertyName));
        status = AJ_OK;
    }

    return status;
}



/* All times are expressed in milliseconds. */
#define CONNECT_TIMEOUT     (1000 * 60)
#define SLEEP_TIME          (1000 * 2)

/* SIGINT signal handler. */
static void SigIntHandler(int sig)
{
    ((void)(sig));
    if (s_connected) {
        AJ_Disconnect(&s_busAttachment);
    }
    AJ_AlwaysPrintf(("\nsignal_service exiting after SIGINT (OK)\n"));
    exit(0);
}

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;

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
            status = AJ_StartService(&s_busAttachment,
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

            AJ_InfoPrintf(("StartService returned %d\n", status));
            s_connected = TRUE;
        }

        status = AJ_UnmarshalMsg(&s_busAttachment, &msg, AJ_UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    uint32_t sessionId;

                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    status = AJ_BusReplyAcceptSession(&msg, TRUE);
                    AJ_InfoPrintf(("Accepted session. Port=%u, session_id=%u joiner='%s'.\n",
                                   port, sessionId, joiner));
                }
                break;

            case BASIC_SIGNAL_SERVICE_GET_NAME:
                status = AJ_BusPropGet(&msg, GetName, NULL);
                break;

            case BASIC_SIGNAL_SERVICE_SET_NAME:
                status = AJ_BusPropSet(&msg, SetName, NULL);
                if (AJ_OK == status) {
                    status = SendSignal();
                    AJ_InfoPrintf(("SendSignal reports status 0x%04x.\n", status));
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u", id, reason));
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
            AJ_Disconnect(&s_busAttachment);
            s_connected = FALSE;

            /* Sleep a little while before trying to reconnect. */
            AJ_Sleep(SLEEP_TIME);
        }
    }

    AJ_AlwaysPrintf(("Basic service exiting with status 0x%04x.\n", status));

    return status;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
