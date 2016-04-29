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
#define AJ_MODULE PROP_WITH_ERROR_TEST_SVC


#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_debug.h>

/*
 * Modify these variables to change the service's behavior
 */
static const char ServiceName[] = "org.alljoyn.prop_test";
static const uint16_t ServicePort = 24;
static const uint8_t CancelAdvertiseName = FALSE;


static const char* const testValuesInterface[] = {
    "org.alljoyn.alljoyn_test.values",
    "@int_val=i",
    "@str_val=s",
    "@ro_val>s",
    NULL
};

static const AJ_InterfaceDescription testInterfaces[] = {
    AJ_PropertiesIface,
    testValuesInterface,
    NULL
};

static AJ_Object AppObjects[] = {
    { "/org/alljoyn/alljoyn_test", testInterfaces, AJ_OBJ_FLAG_ANNOUNCED },
    { NULL }
};

/*
 * Message identifiers for the method calls this application implements
 */
#define APP_GET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define APP_GET_ALL_PROPS   AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET_ALL)
#define APP_SET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)


static AJ_Status PropGetHandler(AJ_Message* replyMsg, uint32_t propId, char* errorName, char* errorMessage, void* context)
{
    /* Simulate that an error occurred while trying to read a property */
    strcpy(errorName, "GetPropertyError");
    strcpy(errorMessage, "Error getting property");
    return AJ_ERR_UNEXPECTED;
}


static AJ_Status PropSetHandler(AJ_Message* replyMsg, uint32_t propId, char* errorName, char* errorMessage, void* context)
{
    /* Simulate that an error occurred while trying to apply a property */
    strcpy(errorName, "SetPropertyError");
    strcpy(errorMessage, "Error setting property");
    return AJ_ERR_UNEXPECTED;
}


#define CONNECT_TIMEOUT    (1000 * 1000)
#define UNMARSHAL_TIMEOUT  (1000 * 5)

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

    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);


    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartService(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServicePort, ServiceName, AJ_NAME_REQ_DO_NOT_QUEUE, NULL);
            if (status != AJ_OK) {
                continue;
            }
            AJ_InfoPrintf(("StartService returned AJ_OK\n"));
            AJ_InfoPrintf(("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus)));

            connected = TRUE;
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);

        if (status == AJ_ERR_TIMEOUT) {
            continue;
        }

        if (status == AJ_OK) {
            switch (msg.msgId) {

            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    if (port == ServicePort) {
                        status = AJ_BusReplyAcceptSession(&msg, TRUE);
                        AJ_InfoPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
                    } else {
                        status = AJ_ResetArgs(&msg);
                        if (AJ_OK != status) {
                            break;
                        }
                        status = AJ_BusHandleBusMessage(&msg);
                    }
                }
                break;

            case APP_GET_PROP:
                status = AJ_BusPropGetWithError(&msg, PropGetHandler, NULL);
                AJ_AlwaysPrintf(("AJ_BusPropGetWithError() returned %s\n", AJ_StatusText(status)));
                break;

            case APP_GET_ALL_PROPS:
                status = AJ_BusPropGetAllWithError(&msg, PropGetHandler, NULL);
                AJ_AlwaysPrintf(("AJ_BusPropGetAllWithError() returned %s\n", AJ_StatusText(status)));
                break;

            case APP_SET_PROP:
                status = AJ_BusPropSetWithError(&msg, PropSetHandler, NULL);
                AJ_AlwaysPrintf(("AJ_BusPropSetWithError() returned %s\n", AJ_StatusText(status)));
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_InfoPrintf(("Session lost. ID = %u, reason = %u", id, reason));
                    if (CancelAdvertiseName) {
                        status = AJ_BusAdvertiseName(&bus, ServiceName, AJ_TRANSPORT_ANY, AJ_BUS_START_ADVERTISING, 0);
                    }
                    status = AJ_ERR_SESSION_LOST;
                }
                break;

            case AJ_SIGNAL_SESSION_JOINED:
                if (CancelAdvertiseName) {
                    status = AJ_BusAdvertiseName(&bus, ServiceName, AJ_TRANSPORT_ANY, AJ_BUS_STOP_ADVERTISING, 0);
                }
                break;

            default:
                /*
                 * Pass to the built-in bus message handlers
                 */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }

        }
        /*
         * Unmarshaled messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_READ) || (status == AJ_ERR_LINK_DEAD)) {
            AJ_AlwaysPrintf(("AllJoyn disconnect\n"));
            AJ_AlwaysPrintf(("Disconnected from Daemon:%s\n", AJ_GetUniqueName(&bus)));
            AJ_Disconnect(&bus);
            connected = FALSE;
            /*
             * Sleep a little while before trying to reconnect
             */
            AJ_Sleep(10 * 1000);
        }
    }
    AJ_AlwaysPrintf(("Exiting prop_with_error_test_svc with status %s\n", AJ_StatusText(status)));

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
