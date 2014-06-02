/*
 * clientlite.c
 */

/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE CLIENTLITE

#include <aj_target.h>
#include <alljoyn.h>
#include "aj_config.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
uint8_t dbgCLIENTLITE = 0;

/*
 * The app should authenticate the peer if one or more interfaces are secure
 * To define a secure interface, prepend '$' before the interface name, eg., "$org.alljoyn.alljoyn_test"
 */
#ifdef SECURE_INTERFACE
#ifdef NO_AUTH_PIN_KEYX
#error "You are defining a secure interface but not using authentication\n"
#endif
static const char testInterfaceName[] = "$org.alljoyn.alljoyn_test";
static const char testValuesInterfaceName[] = "$org.alljoyn.alljoyn_test.values";
#else
static const char testInterfaceName[] = "org.alljoyn.alljoyn_test";
static const char testValuesInterfaceName[] = "org.alljoyn.alljoyn_test.values";
#endif

#ifndef NGNS
static const char testServiceName[] = "org.alljoyn.svclite";
static const uint16_t testServicePort = 24;
#else
static char testServiceName[AJ_MAX_NAME_SIZE + 1];
static const char* testInterfaceNames[] = {
    testInterfaceName,
    testValuesInterfaceName,
    NULL
};
#endif

static const char* const testInterface[] = {
    testInterfaceName,
    "?my_ping inStr<s outStr>s",
    NULL
};

static const char* const testValuesInterface[] = {
    testValuesInterfaceName,
    "@int_val=i",
    NULL
};

static const AJ_InterfaceDescription testInterfaces[] = {
    AJ_PropertiesIface,
    testInterface,
    testValuesInterface,
    NULL
};

static const char testObj[] = "/org/alljoyn/alljoyn_test";

/**
 * Objects implemented by the application
 */
static AJ_Object ProxyObjects[] = {
    { NULL, testInterfaces },    /* Object path will be specified later */
    { NULL }
};

#define PRX_GET_PROP  AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define PRX_SET_PROP  AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define PRX_MY_PING   AJ_PRX_MESSAGE_ID(0, 1, 0)
#define PRX_GET_INT   AJ_PRX_PROPERTY_ID(0, 2, 0)
#define PRX_SET_INT   AJ_PRX_PROPERTY_ID(0, 2, 0)

#define CONNECT_TIMEOUT    (1000 * 200)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (1000 * 10)
#define PING_TIMEOUT       (1000 * 10)

/*
 * Let the application do some work
 */
static AJ_Status SendPing(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName, unsigned int num);
static int32_t g_iterCount = 0;
static void AppDoWork(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName)
{
    AJ_Printf("AppDoWork\n");
    /*
     * This function is called if there are no messages to unmarshal
     * Alternate between alljoyn_test ping and Bus ping
     */
    g_iterCount = g_iterCount + 1;
    if (g_iterCount & 1) {
        SendPing(bus, sessionId, serviceName, g_iterCount);
    } else {
        AJ_BusPing(bus, serviceName, PING_TIMEOUT);
    }
}

static const char PWD[] = "ABCDEFGH";

#ifdef SECURE_INTERFACE
static uint32_t PasswordCallback(uint8_t* buffer, uint32_t bufLen)
{
    memcpy(buffer, PWD, sizeof(PWD));
    return sizeof(PWD) - 1;
}
#endif

static const char PingString[] = "Ping String";

AJ_Status SendPing(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName, unsigned int num)
{
    AJ_Status status;
    AJ_Message msg;

    /*
     * Since the object path on the proxy object entry was not set in the proxy object table above
     * it must be set before marshalling the method call.
     */
    status = AJ_SetProxyObjectPath(ProxyObjects, PRX_MY_PING, testObj);
    if (status == AJ_OK) {
        status = AJ_MarshalMethodCall(bus, &msg, PRX_MY_PING, serviceName, sessionId, 0, METHOD_TIMEOUT);
    }
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", PingString);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status SendGetProp(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, PRX_GET_PROP, serviceName, sessionId, 0, METHOD_TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalPropertyArgs(&msg, PRX_GET_INT);
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status SendSetProp(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName, int val)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, PRX_SET_PROP, serviceName, sessionId, 0, METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalPropertyArgs(&msg, PRX_SET_INT);

        if (status == AJ_OK) {
            status = AJ_MarshalArgs(&msg, "i", val);
        } else {
            AJ_Printf(">>>>>>>>In SendSetProp() AJ_MarshalPropertyArgs() returned status = 0x%04x\n", status);
        }

        if (status == AJ_OK) {
            status = AJ_DeliverMsg(&msg);
        } else {
            AJ_Printf(">>>>>>>>In SendSetProp() AJ_MarshalArgs() returned status = 0x%04x\n", status);
        }
    }

    return status;
}

void AuthCallback(const void* context, AJ_Status status)
{
    *((AJ_Status*)context) = status;
}

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;
    AJ_Status authStatus = AJ_ERR_NULL;

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(ProxyObjects);
    AJ_RegisterObjects(NULL, ProxyObjects);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
#ifndef NGNS
            status = AJ_StartClient(&bus, NULL, CONNECT_TIMEOUT, FALSE, testServiceName, testServicePort, &sessionId, NULL);
#else
            status = AJ_StartClientByInterface(&bus, NULL, CONNECT_TIMEOUT, FALSE, testInterfaceNames, &sessionId, testServiceName, NULL);
#endif
            if (status == AJ_OK) {
                AJ_Printf("StartClient returned %d, sessionId=%u, serviceName=%s\n", status, sessionId, testServiceName);
                AJ_Printf("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus));
                connected = TRUE;
#ifdef SECURE_INTERFACE
                AJ_BusSetPasswordCallback(&bus, PasswordCallback);
                status = AJ_BusAuthenticatePeer(&bus, testServiceName, AuthCallback, &authStatus);
                if (status != AJ_OK) {
                    AJ_Printf("AJ_BusAuthenticatePeer returned %d\n", status);
                }
#else
                authStatus = AJ_OK;
#endif
            } else {
                AJ_Printf("StartClient returned %d\n", status);
                break;
            }
        }

        if (authStatus != AJ_ERR_NULL) {
            if (authStatus != AJ_OK) {
                AJ_Disconnect(&bus);
                break;
            }
            authStatus = AJ_ERR_NULL;
            AJ_BusSetLinkTimeout(&bus, sessionId, 10 * 1000);
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                AppDoWork(&bus, sessionId, testServiceName);
                continue;
            }
        } else {
            switch (msg.msgId) {

            case AJ_REPLY_ID(AJ_METHOD_SET_LINK_TIMEOUT):
                {
                    uint32_t disposition;
                    uint32_t timeout;
                    status = AJ_UnmarshalArgs(&msg, "uu", &disposition, &timeout);
                    if (disposition == AJ_SETLINKTIMEOUT_SUCCESS) {
                        AJ_Printf("Link timeout set to %d\n", timeout);
                    } else {
                        AJ_Printf("SetLinkTimeout failed %d\n", disposition);
                    }
                    SendPing(&bus, sessionId, testServiceName, 1);
                }
                break;

            case AJ_REPLY_ID(AJ_METHOD_BUS_PING):
                {
                    uint32_t disposition;
                    status = AJ_UnmarshalArgs(&msg, "u", &disposition);
                    if (disposition == AJ_PING_SUCCESS) {
                        AJ_Printf("Bus Ping reply received\n");
                    } else {
                        AJ_Printf("Bus Ping failed, disconnecting: %d\n", disposition);
                        status = AJ_ERR_LINK_DEAD;
                    }
                }
                break;

            case AJ_REPLY_ID(PRX_MY_PING):
                {
                    AJ_Arg arg;
                    AJ_UnmarshalArg(&msg, &arg);
                    AJ_Printf("Got ping reply\n");
                    AJ_InfoPrintf(("INFO Got ping reply\n"));
                    status = SendGetProp(&bus, sessionId, testServiceName);
                }
                break;

            case AJ_REPLY_ID(PRX_GET_PROP):
                {
                    const char* sig;
                    status = AJ_UnmarshalVariant(&msg, &sig);
                    if (status == AJ_OK) {
                        status = AJ_UnmarshalArgs(&msg, sig, &g_iterCount);
                        AJ_Printf("Get prop reply %d\n", g_iterCount);

                        if (status == AJ_OK) {
                            g_iterCount = g_iterCount + 1;
                            status = SendSetProp(&bus, sessionId, testServiceName, g_iterCount);
                        }
                    }
                }
                break;

            case AJ_REPLY_ID(PRX_SET_PROP):
                AJ_Printf("Set prop reply\n");
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /*
                 * Force a disconnect
                 */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_Printf("Session lost. ID = %u, reason = %u", id, reason);
                }
                status = AJ_ERR_SESSION_LOST;
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
            return status;
        }
    }
    AJ_Printf("clientlite EXIT %d\n", status);

    return status;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
