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
#define AJ_MODULE DOORSVC

#define SECURE_INTERFACE
#define SECURE_OBJECT

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_link_timeout.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_auth_listener.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_authorisation.h>
#include <ajtcl/aj_security.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
uint8_t dbgDOORSVC = 1;

/*
 * Modify these variables to change the service's behavior
 */
static const char ServiceName[] = "org.alljoyn.doorsvc";
static const uint16_t ServicePort = 12345;

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

static const char doorIfn[] = "sample.securitymgr.door.Door";
static const char doorObj[] = "/sample/security/Door";

/*
 * To define a secure interface, prepend '$' before the interface name, eg., "$org.alljoyn.alljoyn_test"
 */
static const char* const doorInterface[] = {
    doorIfn,
    "?Open success>b",
    "?Close success>b",
    "?GetState state>b",
    "!StateChanged state>b",
    "@State=b",
    NULL
};

static const AJ_InterfaceDescription doorInterfaces[] = {
    AJ_PropertiesIface,
    doorInterface,
    NULL
};

static AJ_Object AppObjects[] = {
    { doorObj, doorInterfaces, AJ_OBJ_FLAG_ANNOUNCED | AJ_OBJ_FLAG_SECURE },
    { NULL }
};

static AJ_PermissionMember members[] = { { "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_PROVIDE | AJ_ACTION_OBSERVE, NULL } };
static AJ_PermissionRule rules[] = { { doorObj, doorIfn, members, NULL } };

#define OPEN   TRUE
#define CLOSED FALSE
static boolean_t state = CLOSED;
/*
 * Message identifiers for the method calls this application implements
 */
#define APP_GET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define APP_SET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define APP_OPEN            AJ_APP_MESSAGE_ID(0, 1, 0)
#define APP_CLOSE           AJ_APP_MESSAGE_ID(0, 1, 1)
#define APP_GET_STATE       AJ_APP_MESSAGE_ID(0, 1, 2)
#define APP_STATE_CHANGED   AJ_APP_MESSAGE_ID(0, 1, 3)
#define APP_STATE           AJ_APP_PROPERTY_ID(0, 1, 4)

/*
 * Let the application do some work
 */
static void AppDoWork()
{
    /*
     * This function is called if there are no messages to unmarshal
     */
    AJ_InfoPrintf(("do work\n"));
}

#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
static const char psk_hint[] = "<anonymous>";
/*
 * The tests were changed at some point to make the psk longer.
 * If doing backcompatibility testing with previous versions (14.08 or before),
 * define LITE_TEST_BACKCOMPAT to use the old version of the password.
 */
#ifndef LITE_TEST_BACKCOMPAT
static const char psk_char[] = "faaa0af3dd3f1e0379da046a3ab6ca44";
#else
static const char psk_char[] = "123456";
#endif
static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_AlwaysPrintf(("AuthListenerCallback authmechanism %08X command %d\n", authmechanism, command));

    switch (authmechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = keyexpiration;
        status = AJ_OK;
        break;

    case AUTH_SUITE_ECDHE_PSK:
        switch (command) {
        case AJ_CRED_PUB_KEY:
            cred->data = (uint8_t*) psk_hint;
            cred->len = strlen(psk_hint);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;

        case AJ_CRED_PRV_KEY:
            cred->data = (uint8_t*) psk_char;
            cred->len = strlen(psk_char);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;
        }
        break;

    default:
        break;
    }
    return status;
}
#endif

/*
 * Handles a property GET request so marshals the property value to return
 */
static AJ_Status PropGetHandler(AJ_Message* reply, uint32_t id, void* context)
{
    if (id == APP_STATE) {
        return AJ_MarshalArgs(reply, "b", state);
    } else {
        return AJ_ERR_UNEXPECTED;
    }
}

/*
 * Handles a property SET request so unmarshals the property value to apply.
 */
static AJ_Status PropSetHandler(AJ_Message* reply, uint32_t id, void* context)
{
    if (id == APP_STATE) {
        return AJ_UnmarshalArgs(reply, "b", &state);
    } else {
        return AJ_ERR_UNEXPECTED;
    }
}

#define UUID_LENGTH 16
#define APP_ID_SIGNATURE "ay"

static AJ_Status MarshalAppId(AJ_Message* msg, const char* appId)
{
    AJ_Status status;
    uint8_t binAppId[UUID_LENGTH];
    uint32_t sz = strlen(appId);

    if (sz > UUID_LENGTH * 2) { // Crop application id that is too long
        sz = UUID_LENGTH * 2;
    }
    status = AJ_HexToRaw(appId, sz, binAppId, UUID_LENGTH);
    if (status != AJ_OK) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "{sv}", AJ_APP_ID_STR, APP_ID_SIGNATURE, binAppId, sz / 2);

    return status;
}

static AJ_Status AboutPropGetter(AJ_Message* reply, const char* language)
{
    AJ_Status status = AJ_OK;
    AJ_Arg array;
    AJ_GUID theAJ_GUID;
    AJ_Arg dict;
    AJ_Arg languageListArray;
    char machineIdValue[UUID_LENGTH * 2 + 1];

    machineIdValue[UUID_LENGTH * 2] = '\0';

    /* Here, "en" is the only supported language, so we always return it
     * regardless of what was requested, per the algorithm specified in
     * RFC 4647 section 3.4.
     */

    status = AJ_MarshalContainer(reply, &array, AJ_ARG_ARRAY);
    if (status == AJ_OK) {
        status = AJ_GetLocalGUID(&theAJ_GUID);
        if (status == AJ_OK) {
            AJ_GUID_ToString(&theAJ_GUID, machineIdValue, UUID_LENGTH * 2 + 1);
        }
        if (status == AJ_OK) {
            status = MarshalAppId(reply, &machineIdValue[0]);
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_APP_NAME_STR, "s", "doorsvc");
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_DEVICE_ID_STR, "s", machineIdValue);
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_DEVICE_NAME_STR, "s", "Tester");
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_MANUFACTURER_STR, "s", "QCE");
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_MODEL_NUMBER_STR, "s", "1.0");
        }
        //SupportedLanguages
        if (status == AJ_OK) {
            status = AJ_MarshalContainer(reply, &dict, AJ_ARG_DICT_ENTRY);
            if (status == AJ_OK) {
                status = AJ_MarshalArgs(reply, "s", AJ_SUPPORTED_LANGUAGES_STR);
            }
            if (status == AJ_OK) {
                status = AJ_MarshalVariant(reply, "as");
            }
            if (status == AJ_OK) {
                status = AJ_MarshalContainer(reply, &languageListArray, AJ_ARG_ARRAY);
            }
            if (status == AJ_OK) {
                status = AJ_MarshalArgs(reply, "s", "en");
            }
            if (status == AJ_OK) {
                status = AJ_MarshalCloseContainer(reply, &languageListArray);
            }
            if (status == AJ_OK) {
                status = AJ_MarshalCloseContainer(reply, &dict);
            }

        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_DESCRIPTION_STR, "s", "doorsvc test app");
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_DEFAULT_LANGUAGE_STR, "s", "en");
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_SOFTWARE_VERSION_STR, "s", AJ_GetVersion());
        }
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(reply, "{sv}", AJ_AJSOFTWARE_VERSION_STR, "s", AJ_GetVersion());
        }
    }
    if (status == AJ_OK) {
        status = AJ_MarshalCloseContainer(reply, &array);
    }
    return status;
}

uint32_t MyBusAuthPwdCB(uint8_t* buf, uint32_t bufLen)
{
    const char* myPwd = "1234";
    strncpy((char*)buf, myPwd, bufLen);
    return (uint32_t)strlen(myPwd);
}

static const uint32_t suites[] = { AUTH_SUITE_ECDHE_ECDSA, AUTH_SUITE_ECDHE_PSK, AUTH_SUITE_ECDHE_NULL };

#define CONNECT_TIMEOUT    (1000 * 1000)
#define UNMARSHAL_TIMEOUT  (1000 * 5)

#ifdef MAIN_ALLOWS_ARGS
int AJ_Main(int ac, char** av)
#else
int AJ_Main()
#endif
{
    AJ_Message reply;
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;
    AJ_Message msg;
    uint16_t port;
    char* joiner;
    AJ_Message signal;
    uint32_t id, reason;
    uint32_t disposition, idleTo, probeTo;

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);
    AJ_AboutRegisterPropStoreGetter(AboutPropGetter);

    while (TRUE) {

        if (!connected) {
            status = AJ_StartService(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServicePort, ServiceName, AJ_NAME_REQ_DO_NOT_QUEUE, NULL);
            if (status != AJ_OK) {
                continue;
            }
            AJ_InfoPrintf(("StartService returned AJ_OK\n"));
            AJ_InfoPrintf(("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus)));

            AJ_SetIdleTimeouts(&bus, 10, 4);

            connected = TRUE;

#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
            AJ_BusEnableSecurity(&bus, suites, ArraySize(suites));
            AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
            AJ_ManifestTemplateSet(rules);
            AJ_SecuritySetClaimConfig(&bus, APP_STATE_CLAIMABLE, CLAIM_CAPABILITY_ECDHE_NULL, 0);
#endif

            /* Configure timeout for the link to the daemon bus */
            AJ_SetBusLinkTimeout(&bus, 60); // 60 seconds
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (AJ_ERR_TIMEOUT == status && AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(&bus)) {
            status = AJ_ERR_READ;
        }
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                AppDoWork();
                continue;
            }
        }

        if (status == AJ_OK) {
            switch (msg.msgId) {

            case AJ_REPLY_ID(AJ_METHOD_ADD_MATCH):
                if (msg.hdr->msgType == AJ_MSG_ERROR) {
                    AJ_InfoPrintf(("Failed to add match\n"));
                    status = AJ_ERR_FAILURE;
                } else {
                    status = AJ_OK;
                }
                break;

            case AJ_METHOD_ACCEPT_SESSION:
                {
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

            case APP_OPEN:
                AJ_MarshalReplyMsg(&msg, &reply);
                AJ_MarshalArgs(&reply, "b", TRUE);
                AJ_DeliverMsg(&reply);
                if (CLOSED == state) {
                    state = OPEN;
                    AJ_MarshalSignal(&bus, &signal, APP_STATE_CHANGED, msg.sender, msg.sessionId, 0, 0);
                    AJ_MarshalArgs(&signal, "b", state);
                    AJ_DeliverMsg(&signal);
                    AJ_CloseMsg(&signal);
                }
                break;

            case APP_CLOSE:
                AJ_MarshalReplyMsg(&msg, &reply);
                AJ_MarshalArgs(&reply, "b", TRUE);
                AJ_DeliverMsg(&reply);
                if (OPEN == state) {
                    state = CLOSED;
                    AJ_MarshalSignal(&bus, &signal, APP_STATE_CHANGED, msg.sender, msg.sessionId, 0, 0);
                    AJ_MarshalArgs(&signal, "b", state);
                    AJ_DeliverMsg(&signal);
                    AJ_CloseMsg(&signal);
                }
                break;

            case APP_GET_STATE:
                AJ_MarshalReplyMsg(&msg, &reply);
                AJ_MarshalArgs(&reply, "b", state);
                AJ_DeliverMsg(&reply);
                break;

            case APP_GET_PROP:
                status = AJ_BusPropGet(&msg, PropGetHandler, NULL);
                break;

            case APP_SET_PROP:
                status = AJ_BusPropSet(&msg, PropSetHandler, NULL);
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_InfoPrintf(("Session lost. ID = %u, reason = %u", id, reason));
                    status = AJ_ERR_SESSION_LOST;
                }
                break;

            case AJ_SIGNAL_SESSION_JOINED:
                break;

            case AJ_REPLY_ID(AJ_METHOD_CANCEL_ADVERTISE):
            case AJ_REPLY_ID(AJ_METHOD_ADVERTISE_NAME):
                if (msg.hdr->msgType == AJ_MSG_ERROR) {
                    status = AJ_ERR_FAILURE;
                }
                break;

            case AJ_REPLY_ID(AJ_METHOD_BUS_SET_IDLE_TIMEOUTS):
                {
                    if (msg.hdr->msgType == AJ_MSG_ERROR) {
                        status = AJ_ERR_FAILURE;
                    }
                    AJ_UnmarshalArgs(&msg, "uuu", &disposition, &idleTo, &probeTo);
                    AJ_InfoPrintf(("SetIdleTimeouts response disposition=%u idleTimeout=%u probeTimeout=%u\n", disposition, idleTo, probeTo));
                }
                break;

            default:
                /*
                 * Pass to the built-in bus message handlers
                 */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }

            // Any received packets indicates the link is active, so call to reinforce the bus link state
            AJ_NotifyLinkActive();
        }
        /*
         * Unarshaled messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_READ) || (status == AJ_ERR_LINK_DEAD)) {
            AJ_InfoPrintf(("AllJoyn disconnect\n"));
            AJ_InfoPrintf(("Disconnected from Daemon:%s\n", AJ_GetUniqueName(&bus)));
            AJ_Disconnect(&bus);
            connected = FALSE;
            /*
             * Sleep a little while before trying to reconnect
             */
            AJ_Sleep(10 * 1000);
        }
    }
    AJ_WarnPrintf(("doorsvc EXIT %d\n", status));

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
