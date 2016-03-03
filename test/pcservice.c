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
#define AJ_MODULE PROPERTIES_CHANGED

#ifndef TEST_DISABLE_SECURITY
#define SECURE_INTERFACE
#define SECURE_OBJECT
#endif

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
uint8_t dbgPROPERTIES_CHANGED = 0;

/*
 * Modify these variables to change the service's behavior
 */
static const char ServiceName[] = "org.alljoyn.alljoyn_test.PropertiesChanged";
static const uint16_t ServicePort = 789;
static const uint8_t CancelAdvertiseName = FALSE;
static const uint8_t ReflectSignal = FALSE;
#define METHOD_TIMEOUT     (1000 * 10)

/*
 * An application property to SET or GET
 */
static int32_t propVal = 123456;

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;


static const char* const testValuesInterface[] = {
#ifdef SECURE_INTERFACE
    "$org.alljoyn.alljoyn_test.values",
#else
    "org.alljoyn.alljoyn_test.values",
#endif
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
#ifdef SECURE_OBJECT
    { "/org/alljoyn/alljoyn_test/PropertiesChanged", testInterfaces, AJ_OBJ_FLAG_ANNOUNCED | AJ_OBJ_FLAG_SECURE },
#else
    { "/org/alljoyn/alljoyn_test/PropertiesChanged", testInterfaces, AJ_OBJ_FLAG_ANNOUNCED },
#endif
    { NULL }
};

static AJ_PermissionMember members[] = { { "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_PROVIDE | AJ_ACTION_OBSERVE, NULL } };
static AJ_PermissionRule rules[] = { { "/org/alljoyn/alljoyn_test/PropertiesChanged", "org.alljoyn.alljoyn_test.PropertiesChanged", members, NULL } };

/*
 * Message identifiers for the method calls this application implements
 */
#define APP_GET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define APP_SET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define APP_PROP_CHANGED    AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_CHANGED)

/*
 * Property identifiers for the properies this application implements
 */
#define APP_INT_VAL_PROP AJ_APP_PROPERTY_ID(0, 1, 0)

/*
 * Send out PropopertiesChanged with different payloads,
 * based on the number of times AppDoWork has been called.
 * This should exercise different permutations of properties changing.

 *  int_val: every even count
 *  ro_val: every third count
 *  invalidates str_val: every fifth count
 */
static void AppDoWork(AJ_BusAttachment* bus, uint32_t sessionId)
{
    /*
     * This function is called if there are no messages to unmarshal
     */
    AJ_Status status;
    AJ_Message msg;
    AJ_Arg array;
    static uint8_t count = 0;

    AJ_InfoPrintf(("do work\n"));

    status = AJ_MarshalSignal(bus, &msg, APP_PROP_CHANGED, NULL, sessionId, 0, METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", testValuesInterface[0]);
    }

    // now create the array of dictionary entries and their values
    if (status == AJ_OK) {
        status = AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);
    }
    if (status == AJ_OK) {
        if (count % 2 == 0) {
            status = AJ_MarshalArgs(&msg, "{sv}", "int_val", "i", propVal);
        }
        if (count % 3 == 0) {
            status = AJ_MarshalArgs(&msg, "{sv}", "ro_val", "s", "ro_val mod 4");
        }
    }
    if (status == AJ_OK) {
        status = AJ_MarshalCloseContainer(&msg, &array);
    }

    // and one entry in the invalidated property array
    if (status == AJ_OK) {
        status = AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);
    }
    if (status == AJ_OK) {
        if (count % 5 == 0) {
            status = AJ_MarshalArgs(&msg, "s", "str_val");
        }
    }
    if (status == AJ_OK) {
        status = AJ_MarshalCloseContainer(&msg, &array);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    } else {
        AJ_AlwaysPrintf(("AppDoWork %s\n", AJ_StatusText(status)));
    }
    AJ_CloseMsg(&msg);
    propVal++;
    count++;
}

#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
static const char psk_hint[] = "<anonymous>";
/*
 * The tests were changed at some point to make the psk longer.
 * If doing backcompatibility testing with previous versions (14.06 or before),
 * define LITE_TEST_BACKCOMPAT to use the old version of the password.
 */
#ifndef LITE_TEST_BACKCOMPAT
static const char psk_char[] = "faaa0af3dd3f1e0379da046a3ab6ca44";
#else
static const char psk_char[] = "123456";
#endif

// Copied from alljoyn/alljoyn_core/unit_test/AuthListenerECDHETest.cc with
// newlines removed
static const char pem_prv[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MDECAQEEICCRJMbxSiWUqj4Zs7jFQRXDJdBRPWX6fIVqE1BaXd08oAoGCCqGSM49"
    "AwEH"
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBuDCCAV2gAwIBAgIHMTAxMDEwMTAKBggqhkjOPQQDAjBCMRUwEwYDVQQLDAxv"
    "cmdhbml6YXRpb24xKTAnBgNVBAMMIDgxM2FkZDFmMWNiOTljZTk2ZmY5MTVmNTVk"
    "MzQ4MjA2MB4XDTE1MDcyMjIxMDYxNFoXDTE2MDcyMTIxMDYxNFowQjEVMBMGA1UE"
    "CwwMb3JnYW5pemF0aW9uMSkwJwYDVQQDDCAzOWIxZGNmMjBmZDJlNTNiZGYzMDU3"
    "NzMzMjBlY2RjMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGJ/9F4xHn3Klw7z"
    "6LREmHJgzu8yJ4i09b4EWX6a5MgUpQoGKJcjWgYGWb86bzbciMCFpmKzfZ42Hg+k"
    "BJs2ZWajPjA8MAwGA1UdEwQFMAMBAf8wFQYDVR0lBA4wDAYKKwYBBAGC3nwBATAV"
    "BgNVHSMEDjAMoAoECELxjRK/fVhaMAoGCCqGSM49BAMCA0kAMEYCIQDixoulcO7S"
    "df6Iz6lvt2CDy0sjt/bfuYVW3GeMLNK1LAIhALNklms9SP8ZmTkhCKdpC+/fuwn0"
    "+7RX8CMop11eWCih"
    "-----END CERTIFICATE-----"
};

static X509CertificateChain* chain = NULL;
static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;
    X509CertificateChain* node;

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

    case AUTH_SUITE_ECDHE_ECDSA:
        switch (command) {
        case AJ_CRED_PRV_KEY:
            AJ_ASSERT(sizeof (AJ_ECCPrivateKey) == cred->len);
            if (sizeof (AJ_ECCPrivateKey) != cred->len) {
                AJ_ErrPrintf(("Credential length mismatch.\n"));
                status = AJ_ERR_INVALID;
                break;
            }
            status = AJ_DecodePrivateKeyPEM((AJ_ECCPrivateKey*) cred->data, pem_prv);
            cred->expiration = keyexpiration;
            break;

        case AJ_CRED_CERT_CHAIN:
            switch (cred->direction) {
            case AJ_CRED_REQUEST:
                // Free previous certificate chain
                AJ_X509FreeDecodedCertificateChain(chain);
                chain = AJ_X509DecodeCertificateChainPEM(pem_x509);
                if (NULL == chain) {
                    return AJ_ERR_INVALID;
                }
                cred->data = (uint8_t*) chain;
                cred->expiration = keyexpiration;
                status = AJ_OK;
                break;

            case AJ_CRED_RESPONSE:
                node = (X509CertificateChain*) cred->data;
#ifdef LITE_TEST_BACKCOMPAT
                status = AJ_X509VerifyChain(node, NULL, 0);
#else
                status = AJ_X509VerifyChain(node, NULL, AJ_CERTIFICATE_IDN_X509);
#endif
                while (node) {
                    AJ_DumpBytes("CERTIFICATE", node->certificate.der.data, node->certificate.der.size);
                    node = node->next;
                }
                break;
            }
            break;
        }
        break;

    default:
        break;
    }
    return status;
}
#endif

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
            status = AJ_MarshalArgs(reply, "{sv}", AJ_APP_NAME_STR, "s", "properties_changed_service");
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
            AJ_Arg dict;
            AJ_Arg languageListArray;
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
            status = AJ_MarshalArgs(reply, "{sv}", AJ_DESCRIPTION_STR, "s", "properties changed test app");
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

static const uint32_t suites[] = { AUTH_SUITE_ECDHE_ECDSA, AUTH_SUITE_ECDHE_PSK, AUTH_SUITE_ECDHE_NULL };

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
    uint8_t claim = FALSE;

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);
    AJ_AboutRegisterPropStoreGetter(AboutPropGetter);

#ifdef MAIN_ALLOWS_ARGS
    ac--;
    av++;
    if (ac) {
#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
        if (0 == strncmp(*av, "-claim", 6)) {
            claim = TRUE;
        }
#endif
    }
#endif

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartService(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServicePort, ServiceName, AJ_NAME_REQ_DO_NOT_QUEUE, NULL);
            if (status != AJ_OK) {
                continue;
            }
            AJ_InfoPrintf(("StartService returned AJ_OK\n"));
            AJ_InfoPrintf(("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus)));

            AJ_SetIdleTimeouts(&bus, 10, 4);

            connected = TRUE;
#ifdef SECURE_OBJECT
            status = AJ_SetObjectFlags("/org/alljoyn/alljoyn_test/PropertiesChanged", AJ_OBJ_FLAG_SECURE, 0);
            if (status != AJ_OK) {
                AJ_ErrPrintf(("Error calling AJ_SetObjectFlags.. [%s] \n", AJ_StatusText(status)));
                return -1;
            }
#endif

#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)

            AJ_BusEnableSecurity(&bus, suites, ArraySize(suites));
            AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
            AJ_ManifestTemplateSet(rules);
            if (claim) {
                AJ_SecuritySetClaimConfig(&bus, APP_STATE_CLAIMABLE, CLAIM_CAPABILITY_ECDHE_PSK, 0);
            }
#endif

            /* Configure timeout for the link to the daemon bus */
            AJ_SetBusLinkTimeout(&bus, 60); // 60 seconds
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if ((AJ_ERR_TIMEOUT == status) && (AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(&bus))) {
            status = AJ_ERR_READ;
        }
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                AppDoWork(&bus, sessionId);
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
                    uint16_t port;
                    char* joiner;
                    status = AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    if (AJ_OK != status) {
                        break;
                    }
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

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    uint32_t id, reason;
                    status = AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    if (AJ_OK != status) {
                        break;
                    }
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

            case AJ_REPLY_ID(AJ_METHOD_CANCEL_ADVERTISE):
            case AJ_REPLY_ID(AJ_METHOD_ADVERTISE_NAME):
                if (msg.hdr->msgType == AJ_MSG_ERROR) {
                    status = AJ_ERR_FAILURE;
                }
                break;

            case AJ_REPLY_ID(AJ_METHOD_BUS_SET_IDLE_TIMEOUTS):
                {
                    uint32_t disposition, idleTo, probeTo;
                    if (msg.hdr->msgType == AJ_MSG_ERROR) {
                        status = AJ_ERR_FAILURE;
                    }
                    status = AJ_UnmarshalArgs(&msg, "uuu", &disposition, &idleTo, &probeTo);
                    if (AJ_OK != status) {
                        break;
                    }

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
    AJ_WarnPrintf(("properties_changed_service EXIT %d\n", status));

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
