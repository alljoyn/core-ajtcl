/*
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

#include <gtest/gtest.h>

#define AJ_MODULE SECURITYTEST

extern "C" {
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_auth_listener.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_authorisation.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_peer.h>
}

#ifndef NDEBUG
uint8_t dbgSECURITYTEST = 0;
#endif

#define CONNECT_TIMEOUT    (1000ul * 15)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (1000 * 10)
#define PING_TIMEOUT       (1000 * 10)




/*Interface */
static const char* const Test1_Interface1[] = { "$org.alljoyn.alljoyn_test", "?my_ping inStr<s outStr>s", NULL };
static const AJ_InterfaceDescription Test1_Interfaces[] = { AJ_PropertiesIface, Test1_Interface1, NULL };
static const char testObj[] = "/org/alljoyn/alljoyn_test";
static AJ_Object AppObjects[] = {
    { testObj, Test1_Interfaces, AJ_OBJ_FLAG_SECURE },
    { NULL }
};

uint32_t TEST1_APP_MY_PING    = AJ_PRX_MESSAGE_ID(0, 1, 0);
/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

static AJ_BusAttachment testBus;
static const char ServiceName[] = "org.alljoyn.svclite";
static const uint16_t ServicePort = 24;
static char g_ServiceName[AJ_MAX_SERVICE_NAME_SIZE];

class SecurityTest : public testing::Test {
  public:

    SecurityTest() { authStatus = AJ_ERR_NULL; }

    static void AuthCallback(const void* context, AJ_Status status)
    {
        *((AJ_Status*)context) = status;
        ASSERT_EQ(AJ_OK, status) << "Auth callback returns fail " << AJ_StatusText(status);
    }

    AJ_Status authStatus;
};

// Copied from alljoyn/alljoyn_core/unit_test/AuthListenerECDHETest.cc with
// newlines removed
static const char pem_prv[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIBiLw29bf669g7MxMbXK2u8Lp5//w7o4OiVGidJdKAezoAoGCCqGSM49"
    "AwEHoUQDQgAE+A0C9YTghZ1vG7198SrUHxFlhtbSsmhbwZ3N5aQRwzFXWcCCm38k"
    "OzJEmS+venmF1o/FV0W80Mcok9CWlV2T6A=="
    "-----END EC PRIVATE KEY-----"
};

/*
 * Order of certificates is important.
 */
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

/*
 * Order of certificates is important.
 * Generated using alljoyn/common/unit_test/CertificateECCTest.cc (CreateIdentityCertificateChain)
 */
static const char pem_x509_identity[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBMDCB1qADAgECAgIwMzAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjMwHhcN"
    "MTUwODI2MTEzMDIzWhcNMTUwODI2MTQxNzAzWjAOMQwwCgYDVQQDDANjbjQwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAASTTwSwpfZ2AD2G6L6IrLYQ2ilJaxf3egzh"
    "3fuVdPgqopLCJydVei63lQsv2BbbpbKeKg+BAEeoi+MlAWkHBRLIoyQwIjAJBgNV"
    "HRMEAjAAMBUGA1UdJQQOMAwGCisGAQQBgt58AQEwCgYIKoZIzj0EAwIDSQAwRgIh"
    "ANxz/NwcmLw/9Unq/qZpmlCzuwGYh9lZV0S0k8N15MGDAiEAzuzWOBPbC1jXWBfa"
    "q3I41fDrdnnEhV9PyXooXfe70bg="
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBMzCB2aADAgECAgIwMzAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjIwHhcN"
    "MTUwODI2MTEzMDIzWhcNMTUwODI2MTQxNzAzWjAOMQwwCgYDVQQDDANjbjMwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAASj7JGFzIBpVMDf63liqkquAW3sUi6GklEe"
    "BJhdQDnmPfpVrmL90O73hRr0JC1O7NS/mDTmFRRrhwY5XrOwl3vdoycwJTAMBgNV"
    "HRMEBTADAQH/MBUGA1UdJQQOMAwGCisGAQQBgt58AQEwCgYIKoZIzj0EAwIDSQAw"
    "RgIhAIP2cJiWPSvcbMwTr7+OgwjeMVjWuppKtaJoCR8B+u/TAiEArBgP12n77UPO"
    "MC2mZBbPOkdZf+1b76gHpUCLhJWC3ac="
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBMTCB2aADAgECAgIwMjAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjEwHhcN"
    "MTUwODI2MTEzMDIzWhcNMTUwODI2MTQxNzAzWjAOMQwwCgYDVQQDDANjbjIwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAAS3+VvzdzNb39HuMosBcy0GxH5nJ863Dldm"
    "3nWAz3lTkpUZRdmdpp/g7l+W6P6MDWiISWZwQs6acq89iBzPhIvIoycwJTAMBgNV"
    "HRMEBTADAQH/MBUGA1UdJQQOMAwGCisGAQQBgt58AQEwCgYIKoZIzj0EAwIDRwAw"
    "RAIgM1EeCtOLEzHx2FLMkFSQnhDM1MdIsMuyFNarbcKWyxoCIFGdLoQu6GKL/HTS"
    "G9Z66NDZHbjAWKcblpGPiR8DaKza"
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBMjCB2aADAgECAgIwMTAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjEwHhcN"
    "MTUwODI2MTEzMDIzWhcNMTUwODI2MTQxNzAzWjAOMQwwCgYDVQQDDANjbjEwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQdRwW/PnAh8S10PHNOyibARy3Ta1to5Lk6"
    "9c7UkzaaTMNkxTXmuQZoVxa4W5McUTW38Ue5UqRlf54I3+iYtHPioycwJTAMBgNV"
    "HRMEBTADAQH/MBUGA1UdJQQOMAwGCisGAQQBgt58AQEwCgYIKoZIzj0EAwIDSAAw"
    "RQIhAJAOFdOy3PkaBAHNnrpPOqv/cZqnjEEjgfZ0Rlk/MkmAAiAqVRqMJG/TJ9x/"
    "xTG8S3EeCxozIK59I0etjDH+pH+VkQ=="
    "-----END CERTIFICATE-----"
};

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
static X509CertificateChain* chain = NULL;
static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential*cred)
{
    AJ_Status status = AJ_ERR_INVALID;
    X509CertificateChain* node;

    AJ_AlwaysPrintf(("AuthListenerCallback authmechanism %d command %d\n", authmechanism, command));

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
            status = AJ_DecodePrivateKeyPEM((AJ_ECCPrivateKey*) cred->data, pem_prv);
            cred->expiration = keyexpiration;
            break;

        case AJ_CRED_CERT_CHAIN:
            switch (cred->direction) {
            case AJ_CRED_REQUEST:
                // Free previous certificate chain
                while (chain) {
                    node = chain;
                    chain = chain->next;
                    AJ_Free(node->certificate.der.data);
                    AJ_Free(node);
                }
                /* PEM string is end entity..root order */
                /* Decoded chain is root..end entity order */
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
                while (node) {
                    AJ_DumpBytes("CERTIFICATE", node->certificate.der.data, node->certificate.der.size);
                    node = node->next;
                }
                status = AJ_OK;
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

static const char PingString[] = "Ping String";

TEST_F(SecurityTest, DISABLED_Test_ECDHE_NULL)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_Message call;
    char* value;
    uint32_t suites[AJ_AUTH_SUITES_NUM];
    size_t numsuites = 0;
    uint32_t session;

    AJ_Initialize();
    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    status = AJ_StartClientByName(&testBus, NULL, CONNECT_TIMEOUT, FALSE, ServiceName, ServicePort, &session, NULL, g_ServiceName);
    ASSERT_EQ(AJ_OK, status) << "Unable to connect to the daemon. " << "The status returned is " << AJ_StatusText(status);
    if (AJ_OK == status) {
        AJ_Printf("Connected to the bus. The unique name is %s\n", AJ_GetUniqueName(&testBus));
    }

    suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
    status = AJ_BusEnableSecurity(&testBus, suites, numsuites);
    ASSERT_EQ(AJ_OK, status) << "Unable to enable security. " << "The status returned is " << AJ_StatusText(status);
    AJ_BusSetAuthListenerCallback(&testBus, AuthListenerCallback);

    status = AJ_BusAuthenticatePeer(&testBus, ServiceName, AuthCallback, &authStatus);

    while (TRUE) {
        status = AJ_SetProxyObjectPath(AppObjects, TEST1_APP_MY_PING, testObj);
        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (authStatus == AJ_OK) {
                ASSERT_EQ(AJ_OK, AJ_MarshalMethodCall(&testBus, &call, TEST1_APP_MY_PING, ServiceName, session, 0, 5000));
                ASSERT_EQ(AJ_OK, AJ_MarshalArgs(&call, "s", PingString));
                ASSERT_EQ(AJ_OK, AJ_DeliverMsg(&call));
                authStatus = AJ_ERR_NULL;
            }
        } else if (msg.msgId == AJ_REPLY_ID(TEST1_APP_MY_PING)) {
            status = AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_EQ(AJ_OK, status);
            ASSERT_STREQ(PingString, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }
        AJ_CloseMsg(&msg);
    }

    AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
    ASSERT_EQ(AJ_OK, status) << "AJ_ClearCredentials returned status. " << AJ_StatusText(status);
    AJ_Disconnect(&testBus);
}

TEST_F(SecurityTest, DISABLED_Test_ECDHE_PSK)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_Message call;
    char* value;
    uint32_t suites[AJ_AUTH_SUITES_NUM];
    size_t numsuites = 0;
    uint32_t session;

    AJ_Initialize();
    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    status = AJ_StartClientByName(&testBus, NULL, CONNECT_TIMEOUT, FALSE, ServiceName, ServicePort, &session, NULL, g_ServiceName);
    ASSERT_EQ(AJ_OK, status) << "Unable to connect to the daemon. " << "The status returned is " << AJ_StatusText(status);
    if (AJ_OK == status) {
        AJ_Printf("Connected to the bus. The unique name is %s\n", AJ_GetUniqueName(&testBus));
    }

    suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
    status = AJ_BusEnableSecurity(&testBus, suites, numsuites);
    ASSERT_EQ(AJ_OK, status) << "Unable to enable security. " << "The status returned is " << AJ_StatusText(status);
    AJ_BusSetAuthListenerCallback(&testBus, AuthListenerCallback);
    status = AJ_BusAuthenticatePeer(&testBus, ServiceName, AuthCallback, &authStatus);

    while (TRUE) {
        status = AJ_SetProxyObjectPath(AppObjects, TEST1_APP_MY_PING, testObj);
        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (authStatus == AJ_OK) {
                ASSERT_EQ(AJ_OK, AJ_MarshalMethodCall(&testBus, &call, TEST1_APP_MY_PING, ServiceName, session, 0, 5000));
                ASSERT_EQ(AJ_OK, AJ_MarshalArgs(&call, "s", PingString));
                ASSERT_EQ(AJ_OK, AJ_DeliverMsg(&call));
                authStatus = AJ_ERR_NULL;
            }
        } else if (msg.msgId == AJ_REPLY_ID(TEST1_APP_MY_PING)) {
            status = AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_EQ(AJ_OK, status);
            ASSERT_STREQ(PingString, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }
        AJ_CloseMsg(&msg);
    }

    AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
    ASSERT_EQ(AJ_OK, status) << "AJ_ClearCredentials returned status. " << AJ_StatusText(status);
    AJ_Disconnect(&testBus);
}

TEST_F(SecurityTest, DISABLED_Test_ECDHE_ECDSA)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_Message call;
    char* value;
    uint32_t suites[AJ_AUTH_SUITES_NUM];
    size_t numsuites = 0;
    uint32_t session;

    AJ_Initialize();
    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    status = AJ_StartClientByName(&testBus, NULL, CONNECT_TIMEOUT, FALSE, ServiceName, ServicePort, &session, NULL, g_ServiceName);
    ASSERT_EQ(AJ_OK, status) << "Unable to connect to the daemon" << "The status returned is " << AJ_StatusText(status);
    if (AJ_OK == status) {
        AJ_Printf("Connected to the bus. The unique name is %s\n", AJ_GetUniqueName(&testBus));
    }

    suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
    status = AJ_BusEnableSecurity(&testBus, suites, numsuites);
    ASSERT_EQ(AJ_OK, status) << "Unable to enable security" << "The status returned is " << AJ_StatusText(status);
    AJ_BusSetAuthListenerCallback(&testBus, AuthListenerCallback);
    status = AJ_BusAuthenticatePeer(&testBus, ServiceName, AuthCallback, &authStatus);

    while (TRUE) {
        status = AJ_SetProxyObjectPath(AppObjects, TEST1_APP_MY_PING, testObj);
        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (authStatus == AJ_OK) {
                ASSERT_EQ(AJ_OK, AJ_MarshalMethodCall(&testBus, &call, TEST1_APP_MY_PING, ServiceName, session, 0, 5000));
                ASSERT_EQ(AJ_OK, AJ_MarshalArgs(&call, "s", PingString));
                ASSERT_EQ(AJ_OK, AJ_DeliverMsg(&call));
                authStatus = AJ_ERR_NULL;
            }
        } else if (msg.msgId == AJ_REPLY_ID(TEST1_APP_MY_PING)) {
            status = AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_EQ(AJ_OK, status);
            ASSERT_STREQ(PingString, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }
        AJ_CloseMsg(&msg);
    }

    AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
    ASSERT_EQ(AJ_OK, status) << "AJ_ClearCredentials returned status. " << AJ_StatusText(status);
    AJ_Disconnect(&testBus);
}

TEST_F(SecurityTest, CommonPathTest)
{
    EXPECT_FALSE(AJ_CommonPath("", "Signal1", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("", "Method1", METHOD));
    EXPECT_FALSE(AJ_CommonPath("", "Property1", PROPERTY));

    EXPECT_TRUE(AJ_CommonPath("*", "Signal1", SIGNAL));
    EXPECT_TRUE(AJ_CommonPath("*", "Method1", METHOD));
    EXPECT_TRUE(AJ_CommonPath("*", "Property1", PROPERTY));

    EXPECT_FALSE(AJ_CommonPath("Signal", "Signal1", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("Method", "Method1", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property", "Property1", PROPERTY));

    EXPECT_TRUE(AJ_CommonPath("Signal1", "Signal1", SIGNAL));
    EXPECT_TRUE(AJ_CommonPath("Method1", "Method1", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property1", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Signal1", "Signal1 ", SIGNAL));
    EXPECT_TRUE(AJ_CommonPath("Method1", "Method1 ", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property1 ", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Signal1", "Signal1 >s", SIGNAL));
    EXPECT_TRUE(AJ_CommonPath("Method1", "Method1 >s", METHOD));
    EXPECT_TRUE(AJ_CommonPath("Method1", "Method1 <s", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property1 >s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property1 <s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property1 =s", PROPERTY));

    EXPECT_FALSE(AJ_CommonPath("Signal1", "Signal1>s", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("Method1", "Method1>s", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Method1", "Method1<s", METHOD));
    EXPECT_TRUE(AJ_CommonPath("Property1", "Property1>s", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Property1", "Property1<s", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Property1", "Property1=s", PROPERTY));

    EXPECT_FALSE(AJ_CommonPath("Signal1", "Signal", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("Method1", "Method", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Signal1", "Signal ", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("Method1", "Method ", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property ", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Signal1", "Signal>s", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("Method1", "Method>s", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Method1", "Method<s", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property>s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property<s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property=s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Signal1", "Signal2", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("Method1", "Method2", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property2", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property2>s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property2<s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1", "Property2=s", PROPERTY));

    EXPECT_TRUE(AJ_CommonPath("Signal*", "Signal", SIGNAL));
    EXPECT_TRUE(AJ_CommonPath("Method*", "Method", METHOD));
    EXPECT_TRUE(AJ_CommonPath("Property*", "Property", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Signal*", "Signal ", SIGNAL));
    EXPECT_TRUE(AJ_CommonPath("Method*", "Method ", METHOD));
    EXPECT_TRUE(AJ_CommonPath("Property*", "Property ", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Signal*", "Signal1", SIGNAL));
    EXPECT_TRUE(AJ_CommonPath("Method*", "Method1", METHOD));
    EXPECT_TRUE(AJ_CommonPath("Property*", "Property1", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Property*", "Property1>s", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Property*", "Property1<s", PROPERTY));
    EXPECT_TRUE(AJ_CommonPath("Property*", "Property1=s", PROPERTY));

    EXPECT_FALSE(AJ_CommonPath("Signal1*", "Signal", SIGNAL));
    EXPECT_FALSE(AJ_CommonPath("Method1*", "Method", METHOD));
    EXPECT_FALSE(AJ_CommonPath("Property1*", "Property", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1*", "Property>s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1*", "Property<s", PROPERTY));
    EXPECT_FALSE(AJ_CommonPath("Property1*", "Property=s", PROPERTY));
}

TEST_F(SecurityTest, DecodeAndVerifyCertificateChainTest)
{
    X509CertificateChain* root;
    AJ_Status status = AJ_OK;

    /* PEM string is end entity..root order */
    /* Decoded chain is root..end entity order, order required for AJ_X509VerifyChain */
    root = AJ_X509DecodeCertificateChainPEM(pem_x509);

    ASSERT_TRUE(root != NULL);

    /* This is an Identity certificate */
    ASSERT_EQ(AJ_OK, AJ_X509VerifyChain(root, NULL, AJ_CERTIFICATE_IDN_X509));
    ASSERT_EQ(AJ_ERR_SECURITY, AJ_X509VerifyChain(root, NULL, AJ_CERTIFICATE_MBR_X509));
    ASSERT_EQ(AJ_ERR_SECURITY, AJ_X509VerifyChain(root, NULL, AJ_CERTIFICATE_UNR_X509));
    AJ_X509FreeDecodedCertificateChain(root);
}

TEST_F(SecurityTest, PolicyVerifyCertificateChainTest)
{
    X509CertificateChain* root;
    X509CertificateChain* head;
    X509CertificateChain* intermediate1;
    X509CertificateChain* intermediate2;
    X509CertificateChain* leaf;
    AJ_Status status = AJ_OK;
    AJ_ECCPublicKey pub;
    AJ_PermissionPeer peer;
    AJ_PermissionACL acl;
    AJ_Policy policy;
    AJ_CredField field;
    uint8_t buffer[1024];

    AJ_Initialize();

    /* PEM string is end entity..root order */
    /* Decoded chain is root..end entity order, order required for AJ_X509VerifyChain */
    root = AJ_X509DecodeCertificateChainPEM(pem_x509_identity);

    ASSERT_TRUE(root != NULL);

    head = root;
    ASSERT_TRUE(NULL != head);
    intermediate1 = head->next;
    ASSERT_TRUE(NULL != intermediate1);
    intermediate2 = intermediate1->next;
    ASSERT_TRUE(NULL != intermediate2);
    leaf = intermediate2->next;
    ASSERT_TRUE(NULL != leaf);

    /* This is an Identity certificate */
    EXPECT_EQ(AJ_OK, AJ_X509VerifyChain(head, &head->certificate.tbs.publickey, AJ_CERTIFICATE_IDN_X509));
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_X509VerifyChain(head, &head->certificate.tbs.publickey, AJ_CERTIFICATE_MBR_X509));
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_X509VerifyChain(head, &head->certificate.tbs.publickey, AJ_CERTIFICATE_UNR_X509));

    field.data = buffer;
    field.size = sizeof (buffer);

    policy.specification = 1;
    policy.version = 1;
    policy.acls = &acl;

    acl.peers = &peer;
    acl.rules = NULL;
    acl.next = NULL;

    peer.type = AJ_PEER_TYPE_FROM_CA;
    peer.kid.data = NULL;
    peer.kid.size = 0;
    peer.group.data = NULL;
    peer.group.size = 0;
    peer.next = NULL;

    /* Store root issuer */
    memcpy(&peer.pub, &head->certificate.tbs.publickey, sizeof (AJ_ECCPublicKey));
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_OK, AJ_PolicyVerifyCertificate(&head->certificate, &pub));
    peer.type = AJ_PEER_TYPE_WITH_MEMBERSHIP;
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_OK, AJ_PolicyVerifyCertificate(&head->certificate, &pub));

    /* Store intermediate 1 issuer */
    peer.type = AJ_PEER_TYPE_FROM_CA;
    memcpy(&peer.pub, &intermediate1->certificate.tbs.publickey, sizeof (AJ_ECCPublicKey));
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyVerifyCertificate(&head->certificate, &pub));
    EXPECT_EQ(AJ_OK, AJ_PolicyFindAuthority(head));
    peer.type = AJ_PEER_TYPE_WITH_MEMBERSHIP;
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyVerifyCertificate(&head->certificate, &pub));
    EXPECT_EQ(AJ_OK, AJ_PolicyFindAuthority(head));

    /* Store intermediate 2 issuer */
    peer.type = AJ_PEER_TYPE_FROM_CA;
    memcpy(&peer.pub, &intermediate2->certificate.tbs.publickey, sizeof (AJ_ECCPublicKey));
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyVerifyCertificate(&head->certificate, &pub));
    EXPECT_EQ(AJ_OK, AJ_PolicyFindAuthority(head));
    peer.type = AJ_PEER_TYPE_WITH_MEMBERSHIP;
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyVerifyCertificate(&head->certificate, &pub));
    EXPECT_EQ(AJ_OK, AJ_PolicyFindAuthority(head));

    /* Store leaf issuer (non CA) */
    peer.type = AJ_PEER_TYPE_FROM_CA;
    memcpy(&peer.pub, &leaf->certificate.tbs.publickey, sizeof (AJ_ECCPublicKey));
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyVerifyCertificate(&head->certificate, &pub));
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyFindAuthority(head));
    peer.type = AJ_PEER_TYPE_WITH_MEMBERSHIP;
    ASSERT_EQ(AJ_OK, AJ_PolicyToBuffer(&policy, &field));
    ASSERT_EQ(AJ_OK, AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &field));
    ASSERT_EQ(AJ_OK, AJ_PolicyLoad());
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyVerifyCertificate(&head->certificate, &pub));
    EXPECT_EQ(AJ_ERR_SECURITY, AJ_PolicyFindAuthority(head));

    AJ_X509FreeDecodedCertificateChain(root);
    AJ_PolicyUnload();

    /* Remove policy from keystore */
    AJ_CredentialDelete(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL);
}

TEST_F(SecurityTest, RegisterACLTest)
{
    AJ_AuthorisationRegister(AppObjects, AJ_APP_ID_FLAG);
    AJ_AuthorisationRegister(AJ_StandardObjects, AJ_BUS_ID_FLAG);
    AJ_AuthorisationRegister(AJ_StandardObjects, AJ_BUS_ID_FLAG);
    AJ_AuthorisationRegister(AppObjects, AJ_APP_ID_FLAG);
    AJ_AuthorisationRegister(AJ_StandardObjects, AJ_BUS_ID_FLAG);
    AJ_AuthorisationRegister(AppObjects, AJ_APP_ID_FLAG);
}

class SerialNumberTest : public testing::Test {
  public:
    SerialNumberTest() { }
};

TEST_F(SerialNumberTest, Test1)
{
    AJ_SerialNum prev = { 0, 0 };
    uint32_t curr = 0;
    int i;

    for (i = 0; i < 64; i++) {
        curr++;
        ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
    for (i = 0; i < 64; i++) {
        curr--;
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
}

TEST_F(SerialNumberTest, Test2)
{
    AJ_SerialNum prev = { 0, 0 };
    uint32_t curr = 0;
    int i;

    for (i = 0; i < 32; i++) {
        curr += 2;
        ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
    for (i = 0; i < 32; i++) {
        curr -= 2;
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
}

TEST_F(SerialNumberTest, Test3)
{
    AJ_SerialNum prev = { 0, 0 };
    uint32_t curr = 0xFFFFFFFFUL - 32;
    int i;

    for (i = 0; i < 64; i++) {
        curr++;
        if (curr != 0) {
            ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
        }
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
    for (i = 0; i < 64; i++) {
        curr--;
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
}

TEST_F(SerialNumberTest, Test4)
{
    AJ_SerialNum prev = { 0, 0 };
    uint32_t curr = 0xFFFFFFFFUL - 32;
    int i;

    for (i = 0; i < 32; i++) {
        curr += 2;
        ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
    for (i = 0; i < 32; i++) {
        curr -= 2;
        ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    }
}

TEST_F(SerialNumberTest, Test5)
{
    AJ_SerialNum prev = { 0, 0 };
    uint32_t curr = 64;

    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = curr - 63;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = curr - 1;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x8000UL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x8001UL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x8000UL;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
}

TEST_F(SerialNumberTest, Test6)
{
    AJ_SerialNum prev = { 0, 0 };
    uint32_t curr;

    curr = 0x80000001UL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x10UL;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x0UL;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x60000000UL;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0xFFFFFFFFUL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x1UL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0xFFFFFFFFUL;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x0UL;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x80000001UL;
    ASSERT_EQ(AJ_ERR_INVALID, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x7FFFFFFFUL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0xC0000000UL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
    curr = 0x1UL;
    ASSERT_EQ(AJ_OK, AJ_CheckIncomingSerial(&prev, curr));
}
