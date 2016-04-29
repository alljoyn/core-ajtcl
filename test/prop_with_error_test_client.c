/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE PROP_WITH_ERROR_TEST_CLIENT


#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_debug.h>

static const char testInterfaceName[] = "org.alljoyn.alljoyn_test";
static const char testValuesInterfaceName[] = "org.alljoyn.alljoyn_test.values";


/*
 * Buffer to hold the peer's full service name or unique name.
 */
static char g_peerServiceName[AJ_MAX_SERVICE_NAME_SIZE];

static const uint16_t testServicePort = 24;

static const char* const testValuesInterface[] = {
    testValuesInterfaceName,
    "@int_val=i",
    NULL
};

static const AJ_InterfaceDescription testInterfaces[] = {
    AJ_PropertiesIface,
    testValuesInterface,
    NULL
};

static const char testServiceName[] = "org.alljoyn.prop_test";

static const char testObj[] = "/org/alljoyn/alljoyn_test";

/**
 * Objects implemented by the application
 */
static AJ_Object ProxyObjects[] = {
    { "/org/alljoyn/alljoyn_test", testInterfaces },
    { NULL }
};


#define PRX_GET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define PRX_GET_ALL_PROPS   AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET_ALL)
#define PRX_SET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define PRX_GET_INT         AJ_PRX_PROPERTY_ID(0, 1, 0)
#define PRX_SET_INT         AJ_PRX_PROPERTY_ID(0, 1, 0)

#define CONNECT_TIMEOUT    (1000 * 200)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (1000 * 10)

#define ERROR_MSG_BUF_SIZE 256


AJ_Status SendGetProp(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, PRX_GET_PROP, serviceName, sessionId, 0, METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalPropertyArgs(&msg, PRX_GET_INT);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    } else {
        AJ_AlwaysPrintf(("SendGetProp() returning %s\n", AJ_StatusText(status)));
    }
    return status;
}

AJ_Status SendGetAllProps(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, PRX_GET_ALL_PROPS, serviceName, sessionId, 0, METHOD_TIMEOUT);

    status = AJ_MarshalArgs(&msg, "s", testValuesInterfaceName);

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    } else {
        AJ_AlwaysPrintf(("SendGetAllProps() returning %s\n", AJ_StatusText(status)));
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
    }
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "i", val);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    } else {
        AJ_AlwaysPrintf(("SendSetProp returning %s\n", AJ_StatusText(status)));
    }

    return status;
}



#ifdef MAIN_ALLOWS_ARGS
int AJ_Main(int ac, char** av)
#else
int AJ_Main()
#endif
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(ProxyObjects);
    AJ_RegisterObjects(NULL, ProxyObjects);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartClientByName(&bus, NULL, CONNECT_TIMEOUT, FALSE, testServiceName, testServicePort, &sessionId, NULL, g_peerServiceName);

            if (status == AJ_OK) {
                AJ_AlwaysPrintf(("StartClient returned %d, sessionId=%u, serviceName=%s\n", status, sessionId, g_peerServiceName));
                AJ_AlwaysPrintf(("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus)));
                connected = TRUE;

            } else {
                AJ_AlwaysPrintf(("StartClient returned %d\n", status));
                break;
            }
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                status = SendGetProp(&bus, sessionId, g_peerServiceName);
                continue;
            }
        } else {
            switch (msg.msgId) {

            case AJ_REPLY_ID(PRX_GET_PROP):
                {
                    AJ_AlwaysPrintf(("GetProperty reply received\n"));
                    if (msg.error) {
                        char* tempErrorMsg;
                        char errorMsg[ERROR_MSG_BUF_SIZE] = { '\0' };
                        AJ_UnmarshalArgs(&msg, "s", &tempErrorMsg);
                        strncpy(errorMsg, tempErrorMsg, ERROR_MSG_BUF_SIZE);
                        AJ_AlwaysPrintf(("Error is %s, message is %s\n", msg.error, errorMsg));
                    }

                    AJ_Sleep(1000);
                    status = SendGetAllProps(&bus, sessionId, g_peerServiceName);
                }
                break;

            case AJ_REPLY_ID(PRX_GET_ALL_PROPS):
                {
                    AJ_AlwaysPrintf(("GetAll reply received\n"));
                    if (msg.error) {
                        char* tempErrorMsg;
                        char errorMsg[ERROR_MSG_BUF_SIZE] = { '\0' };
                        AJ_UnmarshalArgs(&msg, "s", &tempErrorMsg);
                        strncpy(errorMsg, tempErrorMsg, ERROR_MSG_BUF_SIZE);
                        AJ_AlwaysPrintf(("Error is %s, message is %s\n", msg.error, errorMsg));
                    }
                    int value = 47;

                    AJ_Sleep(1000);
                    status = SendSetProp(&bus, sessionId, g_peerServiceName, value);
                }
                break;

            case AJ_REPLY_ID(PRX_SET_PROP):
                {
                    AJ_AlwaysPrintf(("SetProperty reply received\n"));
                    if (msg.error) {
                        char* tempErrorMsg;
                        char errorMsg[ERROR_MSG_BUF_SIZE] = { '\0' };
                        AJ_UnmarshalArgs(&msg, "s", &tempErrorMsg);
                        strncpy(errorMsg, tempErrorMsg, ERROR_MSG_BUF_SIZE);
                        AJ_AlwaysPrintf(("Error is %s, message is %s\n", msg.error, errorMsg));
                    }

                    AJ_Sleep(1000);
                    status = SendGetProp(&bus, sessionId, g_peerServiceName);
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /*
                 * Force a disconnect
                 */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u\n", id, reason));
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

        if ((status == AJ_ERR_SESSION_LOST) || (status == AJ_ERR_READ) || (status == AJ_ERR_WRITE) || (status == AJ_ERR_LINK_DEAD)) {
            AJ_AlwaysPrintf(("AllJoyn disconnect\n"));
            AJ_AlwaysPrintf(("Disconnected from Daemon:%s\n", AJ_GetUniqueName(&bus)));
            AJ_Disconnect(&bus);
            break;
        }
    }
    AJ_AlwaysPrintf(("Exiting prop_with_error_test_client with status %s\n", AJ_StatusText(status)));

    return status;
}

#ifdef AJ_MAIN
#ifdef MAIN_ALLOWS_ARGS
int main(int ac, char** av)
{
    return AJ_Main(ac, av);
}
#else
int main()
{
    return AJ_Main();
}
#endif
#endif
