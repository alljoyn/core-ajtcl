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

#define CONNECT_TIMEOUT    (1000ul * 200)
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
    "MHcCAQEEIAzfibK85el6fvczuL5vIaKBiZ5hTTaNIo0LEkvJ2dCMoAoGCCqGSM49"
    "AwEHoUQDQgAE3KsljHhEdm5JLdpRr0g1zw9EMmMqcQJdxYoMr8AAF//G8fujudM9"
    "HMlXLcyBk195YnGp+hY8Tk+QNNA3ZVNavw=="
    "-----END EC PRIVATE KEY-----"
};

/*
 * Order of certificates is important.
 */
static const char pem_x509[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBYTCCAQigAwIBAgIJAKdvmRDLDVWQMAoGCCqGSM49BAMCMCQxIjAgBgNVBAoM"
    "GUFsbEpveW5UZXN0U2VsZlNpZ25lZE5hbWUwHhcNMTUwNzIyMjAxMTA3WhcNMTUw"
    "ODIxMjAxMTA3WjAgMR4wHAYDVQQKDBVBbGxKb3luVGVzdENsaWVudE5hbWUwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAATcqyWMeER2bkkt2lGvSDXPD0QyYypxAl3F"
    "igyvwAAX/8bx+6O50z0cyVctzIGTX3lican6FjxOT5A00DdlU1q/oycwJTAVBgNV"
    "HSUEDjAMBgorBgEEAYLefAEBMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDRwAw"
    "RAIgQsvHZ747URkPCpYtBxi56V1OcMF3oKWnGuz2jazWr4YCICCU5/itaYVt1SzQ"
    "cBYyChWx/4KXL4QKWLdm9/6ispdq"
    "-----END CERTIFICATE-----"
    ""
    "-----BEGIN CERTIFICATE-----"
    "MIIBdDCCARugAwIBAgIJANOdlTtGQiNsMAoGCCqGSM49BAMCMCQxIjAgBgNVBAoM"
    "GUFsbEpveW5UZXN0U2VsZlNpZ25lZE5hbWUwHhcNMTUwNzIyMjAxMTA2WhcNMjkw"
    "MzMwMjAxMTA2WjAkMSIwIAYDVQQKDBlBbGxKb3luVGVzdFNlbGZTaWduZWROYW1l"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfN5/iDyZAHt9zLEvR2/y02jVovfW"
    "U+lxLtDe0I+fTOoZn3WMd3EyZWKKdfela66adLWwzijKpBlXpj5KKQn5vKM2MDQw"
    "IQYDVR0lBBowGAYKKwYBBAGC3nwBAQYKKwYBBAGC3nwBBTAPBgNVHRMBAf8EBTAD"
    "AQH/MAoGCCqGSM49BAMCA0cAMEQCIDT7r6txazffbFN8VxPg3tRuyWvtTNwYiS2y"
    "tn0H/nsaAiBzKmTHjrmhSLmYidtNvcU/OjKzmRHmdGTaURz0s2NBcQ=="
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

TEST_F(SecurityTest, Test_ECDHE_NULL)
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

TEST_F(SecurityTest, Test_ECDHE_PSK)
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
    AJ_BusEnableSecurity(&testBus, suites, numsuites);
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

TEST_F(SecurityTest, Test_ECDHE_ECDSA)
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
    X509CertificateChain* chain;
    X509CertificateChain* head;
    X509CertificateChain* last;
    AJ_Status status = AJ_OK;

    chain = AJ_X509DecodeCertificateChainPEM(pem_x509);

    ASSERT_TRUE(chain != NULL);

    /* AJ_X509VerifyChain expects cert chains in root..end entity order, but the pem_x509 string
     * lists them in end entity..root order, which is the order used as a credential to be presented
     * rather than verified. Reverse the list in place to provide the expected order.
     */
    head = chain;
    last = NULL;
    while (head) {
        X509CertificateChain* temp = head->next;
        head->next = last;
        last = head;
        head = temp;
    }
    chain = last;

    /* This is an Identity certificate */
    ASSERT_EQ(AJ_OK, AJ_X509VerifyChain(chain, NULL, AJ_CERTIFICATE_IDN_X509));
    ASSERT_EQ(AJ_ERR_SECURITY, AJ_X509VerifyChain(chain, NULL, AJ_CERTIFICATE_MBR_X509));
    ASSERT_EQ(AJ_ERR_SECURITY, AJ_X509VerifyChain(chain, NULL, AJ_CERTIFICATE_UNR_X509));
    AJ_X509FreeDecodedCertificateChain(chain);
}

TEST_F(SecurityTest, RegisterACLTest)
{
    AJ_AuthorisationRegister(AppObjects, AJ_APP_ID_FLAG);
    AJ_AuthorisationDeregister(AJ_APP_ID_FLAG);
    AJ_AuthorisationRegister(AJ_StandardObjects, AJ_BUS_ID_FLAG);
    AJ_AuthorisationDeregister(AJ_BUS_ID_FLAG);
    AJ_AuthorisationRegister(AJ_StandardObjects, AJ_BUS_ID_FLAG);
    AJ_AuthorisationRegister(AppObjects, AJ_APP_ID_FLAG);
    AJ_AuthorisationDeregister(AJ_BUS_ID_FLAG);
    AJ_AuthorisationDeregister(AJ_APP_ID_FLAG);
    AJ_AuthorisationRegister(AJ_StandardObjects, AJ_BUS_ID_FLAG);
    AJ_AuthorisationRegister(AppObjects, AJ_APP_ID_FLAG);
    AJ_AuthorisationDeregister(AJ_APP_ID_FLAG);
    AJ_AuthorisationDeregister(AJ_BUS_ID_FLAG);
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
