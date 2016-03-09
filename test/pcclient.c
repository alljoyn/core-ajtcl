/*
 * PROPERTIES_CHANGED.c
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

#define AJ_MODULE PROPERTIES_CHANGED

#ifndef TEST_DISABLE_SECURITY
#define SECURE_INTERFACE
#define SECURE_OBJECT
#endif

#include <ajtcl/aj_target.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_auth_listener.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_config.h>

uint8_t dbgPROPERTIES_CHANGED = 0;

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

/*
 * The app should authenticate the peer if one or more interfaces are secure
 * To define a secure interface, prepend '$' before the interface name, eg., "$org.alljoyn.alljoyn_test"
 */
#ifdef SECURE_INTERFACE
static const char testInterfaceName[] = "$org.alljoyn.alljoyn_test";
static const char testValuesInterfaceName[] = "$org.alljoyn.alljoyn_test.values";
#else
static const char testInterfaceName[] = "org.alljoyn.alljoyn_test";
static const char testValuesInterfaceName[] = "org.alljoyn.alljoyn_test.values";
#endif

#if defined(ANNOUNCE_BASED_DISCOVERY) || defined(NGNS)
static const char* testInterfaceNames[] = {
    testInterfaceName,
    testValuesInterfaceName,
    NULL
};
#else
static const char testServiceName[] = "org.alljoyn.alljoyn_test.PropertiesChanged";
#endif

/*
 * Buffer to hold the peer's full service name or unique name.
 */
#if defined(ANNOUNCE_BASED_DISCOVERY) || defined(NGNS)
static char g_peerServiceName[AJ_MAX_NAME_SIZE + 1];
#else
static char g_peerServiceName[AJ_MAX_SERVICE_NAME_SIZE];
#endif

static const uint16_t testServicePort = 789;

static const char* const testValuesInterface[] = {
    testValuesInterfaceName,
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

static const char testObj[] = "/org/alljoyn/alljoyn_test/PropertiesChanged";

/**
 * Objects implemented by the application
 */

#ifdef SECURE_OBJECT
static AJ_Object ProxyObjects[] = {
    { "/org/alljoyn/alljoyn_test/PropertiesChanged", testInterfaces, AJ_OBJ_FLAG_SECURE },
    { NULL }
};
#else
static AJ_Object ProxyObjects[] = {
    { "/org/alljoyn/alljoyn_test/PropertiesChanged", testInterfaces },
    { NULL }
};
#endif

#define PRX_GET_PROP  AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define PRX_SET_PROP  AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define PRX_PROP_CHANGED  AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_CHANGED)
#define PRX_GET_INT   AJ_PRX_PROPERTY_ID(0, 1, 0)
#define PRX_SET_INT   AJ_PRX_PROPERTY_ID(0, 1, 0)

#define CONNECT_TIMEOUT    (1000 * 200)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define PING_TIMEOUT       (1000 * 10)

/**
 * Peer discovery
 */
#ifdef ANNOUNCE_BASED_DISCOVERY
static void handleMandatoryProps(const char* peerName,
                                 const char* appId,
                                 const char* appName,
                                 const char* deviceId,
                                 const char* deviceName,
                                 const char* manufacturer,
                                 const char* modelNumber,
                                 const char* defaultLanguage)
{
    AJ_AlwaysPrintf(("Mandatory Properties for %s\n", peerName));
    AJ_AlwaysPrintf(("Mandatory property: AppId=\"%s\"\n", (appId == NULL || appId[0] == '\0') ? "N/A" : appId));
    AJ_AlwaysPrintf(("Mandatory property: AppName=\"%s\"\n", (appName == NULL || appName[0] == '\0') ? "N/A" : appName));
    AJ_AlwaysPrintf(("Mandatory property: DeviceId=\"%s\"\n", (deviceId == NULL || deviceId[0] == '\0') ? "N/A" : deviceId));
    AJ_AlwaysPrintf(("Mandatory property: DeviceName=\"%s\"\n", (deviceName == NULL || deviceName[0] == '\0') ? "N/A" : deviceName));
    AJ_AlwaysPrintf(("Mandatory property: Manufacturer=\"%s\"\n", (manufacturer == NULL || manufacturer[0] == '\0') ? "N/A" : manufacturer));
    AJ_AlwaysPrintf(("Mandatory property: ModelNumber=\"%s\"\n", (modelNumber == NULL || modelNumber[0] == '\0') ? "N/A" : modelNumber));
    AJ_AlwaysPrintf(("Mandatory property: DefaultLanguage=\"%s\"\n", (defaultLanguage == NULL || defaultLanguage[0] == '\0') ? "N/A" : defaultLanguage));
}

static void handleOptionalProperty(const char* peerName, const char* key, const char* sig, const AJ_Arg* value) {
    if (strcmp(sig, "s") == 0) {
        AJ_AlwaysPrintf(("Optional Prop: %s=\"%s\"\n", key, value->val.v_string));
    } else {
        AJ_AlwaysPrintf(("Optional Prop: %s=[Not A String]\n", key));
    }
}

static uint8_t FoundNewTestPeer(uint16_t version, uint16_t port, const char* peerName, const char* objPath)
{
    AJ_AlwaysPrintf(("FoundNewTestPeer: version:%u port:%u name:%s path=%s\n", version, port, peerName, objPath));
    if ((strcmp(objPath, testObj) == 0) && (port == testServicePort)) {
        if (g_peerServiceName[0] == '\0') {
            strncpy(g_peerServiceName, peerName, AJ_MAX_NAME_SIZE);
            g_peerServiceName[AJ_MAX_NAME_SIZE] = '\0';
        }
    }

    return FALSE;
}

static uint8_t AcceptNewTestPeer(const char* peerName)
{
    AJ_AlwaysPrintf(("AcceptNewTestPeer: name:%s\n", peerName));
    if ((strcmp(g_peerServiceName, peerName) == 0)) {
        return TRUE;
    }

    return FALSE;
}

static const char* testIFaces[] = {
    "org.alljoyn.alljoyn_test.values"
};

static AJ_AboutPeerDescription pingServicePeer = {
    testIFaces, (uint16_t)(sizeof(testIFaces) / sizeof(*testIFaces)), FoundNewTestPeer, AcceptNewTestPeer, NULL, handleMandatoryProps, handleOptionalProperty
};
#endif

/*
 * Let the application do some work
 */
static void AppDoWork(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName)
{
    AJ_AlwaysPrintf(("AppDoWork\n"));
}

AJ_Status AppProcessPropertiesChanged(AJ_Message* msg)
{
    AJ_Status status;
    const char* sendingInterface;
    AJ_Arg arrayOfChanged;
    AJ_Arg arrayOfInvalidated;

    AJ_AlwaysPrintf(("PROPERTIES CHANGED\n"));

    status = AJ_UnmarshalArgs(msg, "s", &sendingInterface);
    if (status == AJ_OK) {
        AJ_InfoPrintf(("interface name: %s\n", sendingInterface));
        status = AJ_UnmarshalContainer(msg, &arrayOfChanged, AJ_ARG_ARRAY);
    }

    // unmarshal the array of changed properties
    if (status == AJ_OK) {
        while (status == AJ_OK) {
            const char* propName;
            const char* vsig;
            AJ_Arg value;
            AJ_Arg dict;
            status = AJ_UnmarshalContainer(msg, &dict, AJ_ARG_DICT_ENTRY);

            if (status != AJ_OK) {
                break;
            }

            status = AJ_UnmarshalArgs(msg, "s", &propName);
            if (status != AJ_OK) {
                break;
            }
            AJ_AlwaysPrintf(("property name: %s\n", propName));

            status = AJ_UnmarshalVariant(msg, &vsig);
            if (status != AJ_OK) {
                break;
            }
            status = AJ_UnmarshalArg(msg, &value);
            if (status != AJ_OK) {
                break;
            }

            status = AJ_UnmarshalCloseContainer(msg, &dict);
        }
        if (status == AJ_ERR_NO_MORE) {
            status = AJ_UnmarshalCloseContainer(msg, &arrayOfChanged);
        }
    }

    if (status == AJ_OK) {
        // now the invalidated objects
        status = AJ_UnmarshalContainer(msg, &arrayOfInvalidated, AJ_ARG_ARRAY);

        while (status == AJ_OK) {
            const char* propName;

            status = AJ_UnmarshalArgs(msg, "s", &propName);
            if (status != AJ_OK) {
                break;
            }
            AJ_AlwaysPrintf(("invalidated property name: %s\n", propName));

        }
        if (status == AJ_ERR_NO_MORE) {
            status = AJ_UnmarshalCloseContainer(msg, &arrayOfInvalidated);
        }
    }
    return status;
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
    "MHcCAQEEIBiLw29bf669g7MxMbXK2u8Lp5//w7o4OiVGidJdKAezoAoGCCqGSM49"
    "AwEHoUQDQgAE+A0C9YTghZ1vG7198SrUHxFlhtbSsmhbwZ3N5aQRwzFXWcCCm38k"
    "OzJEmS+venmF1o/FV0W80Mcok9CWlV2T6A=="
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBYTCCAQigAwIBAgIJAOVrhhJOre/7MAoGCCqGSM49BAMCMCQxIjAgBgNVBAoM"
    "GUFsbEpveW5UZXN0U2VsZlNpZ25lZE5hbWUwHhcNMTUwODI0MjAxODQ1WhcNMjkw"
    "NTAyMjAxODQ1WjAgMR4wHAYDVQQKDBVBbGxKb3luVGVzdENsaWVudE5hbWUwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAAT4DQL1hOCFnW8bvX3xKtQfEWWG1tKyaFvB"
    "nc3lpBHDMVdZwIKbfyQ7MkSZL696eYXWj8VXRbzQxyiT0JaVXZPooycwJTAVBgNV"
    "HSUEDjAMBgorBgEEAYLefAEBMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDRwAw"
    "RAIgevLUXoJBgUr6nVepBHQiv85CGuxu00V4uoARbH6qu1wCIA54iDRh6wit1zbP"
    "kqkBC015LjxucTf3Y7lNGhXuZRsL"
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBdTCCARugAwIBAgIJAJTFhmdwDWsvMAoGCCqGSM49BAMCMCQxIjAgBgNVBAoM"
    "GUFsbEpveW5UZXN0U2VsZlNpZ25lZE5hbWUwHhcNMTUwODI0MjAxODQ1WhcNMjkw"
    "NTAyMjAxODQ1WjAkMSIwIAYDVQQKDBlBbGxKb3luVGVzdFNlbGZTaWduZWROYW1l"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF0nZmkzuK/2CVf7udexLZnlEB5D+"
    "DBsx3POtsRyZWm2QiI1untDTp0uYp51tkP6wI6Gi5gWxB+86lEIPg4ZpTaM2MDQw"
    "IQYDVR0lBBowGAYKKwYBBAGC3nwBAQYKKwYBBAGC3nwBBTAPBgNVHRMBAf8EBTAD"
    "AQH/MAoGCCqGSM49BAMCA0gAMEUCIQDPQ1VRvdBhhneU5e7OvIFHK3d9XPZA7Fw6"
    "VyeW/P5wIAIgD969ks/z9vQ1yCaVaxmVz63toC1ggp4AnBXqbDy8O+4="
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
                    status = AJ_ERR_INVALID;
                } else {
                    cred->data = (uint8_t*) chain;
                    cred->expiration = keyexpiration;
                    status = AJ_OK;
                }
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


#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
void AuthCallback(const void* context, AJ_Status status)
{
    *((AJ_Status*)context) = status;
}
#endif

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
    AJ_Status authStatus = AJ_ERR_NULL;
#ifdef SECURE_INTERFACE
    uint32_t suites[AJ_AUTH_SUITES_NUM];
    size_t numsuites = 0;
    uint8_t clearkeys = FALSE;
#endif

#ifdef MAIN_ALLOWS_ARGS
#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
    ac--;
    av++;
    /*
     * Enable authentication mechanism by command line
     */
    if (ac) {
        if (0 == strncmp(*av, "-ek", 3)) {
            clearkeys = TRUE;
            ac--;
            av++;
        } else if (0 == strncmp(*av, "-e", 2)) {
            ac--;
            av++;
        }
        if (!ac) {
            AJ_AlwaysPrintf(("-e(k) requires an auth mechanism.\n"));
            return 1;
        }
        while (ac) {
            if (0 == strncmp(*av, "ECDHE_ECDSA", 11)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
            } else if (0 == strncmp(*av, "ECDHE_PSK", 9)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
            } else if (0 == strncmp(*av, "ECDHE_NULL", 10)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
            }
            ac--;
            av++;
        }
    }
#endif
#else
    suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
    clearkeys = TRUE;
#endif

#ifdef SECURE_INTERFACE
    if (numsuites == 0) {
        /* Default security to ECDHE_NULL, if not explicit elsewhere */
        suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
    }
#endif

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(ProxyObjects);
    AJ_RegisterObjects(NULL, ProxyObjects);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
#if defined (ANNOUNCE_BASED_DISCOVERY)
            status = AJ_StartClientByPeerDescription(&bus, NULL, CONNECT_TIMEOUT, FALSE, &pingServicePeer, testServicePort, &sessionId, g_peerServiceName, NULL);
#elif defined (NGNS)
            status = AJ_StartClientByInterface(&bus, NULL, CONNECT_TIMEOUT, FALSE, testInterfaceNames, &sessionId, g_peerServiceName, NULL);
#else
            status = AJ_StartClientByName(&bus, NULL, CONNECT_TIMEOUT, FALSE, testServiceName, testServicePort, &sessionId, NULL, g_peerServiceName);
#endif
            if (status == AJ_OK) {
                AJ_AlwaysPrintf(("StartClient returned %d, sessionId=%u, serviceName=%s\n", status, sessionId, g_peerServiceName));
                AJ_AlwaysPrintf(("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus)));
                connected = TRUE;
#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
                AJ_BusEnableSecurity(&bus, suites, numsuites);
                AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
                if (clearkeys) {
                    AJ_ClearCredentials(AJ_GENERIC_MASTER_SECRET | AJ_CRED_TYPE_GENERIC);
                    AJ_ClearCredentials(AJ_GENERIC_ECDSA_THUMBPRINT | AJ_CRED_TYPE_GENERIC);
                    AJ_ClearCredentials(AJ_GENERIC_ECDSA_KEYS | AJ_CRED_TYPE_GENERIC);
                }
                status = AJ_BusAuthenticatePeer(&bus, g_peerServiceName, AuthCallback, &authStatus);
                if (status != AJ_OK) {
                    AJ_AlwaysPrintf(("AJ_BusAuthenticatePeer returned %d\n", status));
                }
#else
                authStatus = AJ_OK;
#endif
            } else {
                AJ_AlwaysPrintf(("StartClient returned %d\n", status));
                break;
            }
        }


        AJ_AlwaysPrintf(("Auth status %d and AllJoyn status %d\n", authStatus, status));

        if (status == AJ_ERR_RESOURCES) {
            AJ_InfoPrintf(("Peer is busy, disconnecting and retrying auth...\n"));
            AJ_Disconnect(&bus);
            connected = FALSE;
            continue;
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
                AppDoWork(&bus, sessionId, g_peerServiceName);
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
                        AJ_AlwaysPrintf(("Link timeout set to %d\n", timeout));
                    } else {
                        AJ_AlwaysPrintf(("SetLinkTimeout failed %d\n", disposition));
                    }
                    //  inform the routing node we want to see these notifications
                    AJ_BusSetSignalRuleSerial(&bus, "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',arg0='#org.alljoyn.alljoyn_test.values'", AJ_BUS_SIGNAL_ALLOW, 0, NULL);
                }
                break;

            case AJ_REPLY_ID(AJ_METHOD_BUS_PING):
                {
                    uint32_t disposition;
                    status = AJ_UnmarshalArgs(&msg, "u", &disposition);
                    if (disposition == AJ_PING_SUCCESS) {
                        AJ_AlwaysPrintf(("Bus Ping reply received\n"));
                    } else {
                        AJ_AlwaysPrintf(("Bus Ping failed, disconnecting: %d\n", disposition));
                        status = AJ_ERR_LINK_DEAD;
                    }
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

            case PRX_PROP_CHANGED:
                /*
                 * properties changed notification: "sa{sv}as", "interface,changed_props,invalidated_props"
                 */
                status = AppProcessPropertiesChanged(&msg);
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
    AJ_AlwaysPrintf(("PROPERTIES_CHANGED EXIT %d\n", status));

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
