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

/*
 * Order of certificates is important.
 * Generated using alljoyn/common/unit_test/CertificateECCTest.cc (CreateIdentityCertificateChain)
 */
static const char pem_x509_identity[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBQzCB66ADAgECAgIwMzAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjMwHhcN"
    "MTYwMjA5MDA0ODM0WhcNMTYwMjA5MDMzNTE0WjAOMQwwCgYDVQQDDANjbjQwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAASCHIVNOJO98Ce7vGy5IQkKgFdLhU4LJpZp"
    "5UKLZNxYEYTLtPBc1ynq3pty9DVsZ3/dXgzZFLzrA9Ns3tISqXk1ozkwNzAJBgNV"
    "HRMEAjAAMBUGA1UdJQQOMAwGCisGAQQBgt58AQEwEwYDVR0jBAwwCqAIS5ALPthB"
    "n0QwCgYIKoZIzj0EAwIDRwAwRAIgay/Z7JMjDVBIaJ8G0rh35fGwK77c0ytA9nVy"
    "GikbVzECIAjhPpqz9k6z0nlzwsKtOC95JvOC5GD9NHXX96xo5lWZ"
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBSDCB7qADAgECAgIwMzAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjIwHhcN"
    "MTYwMjA5MDA0ODM0WhcNMTYwMjA5MDMzNTE0WjAOMQwwCgYDVQQDDANjbjMwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQK3bAEiq71WbFCXkIN33HP5n1u8c6cAHB4"
    "zYkq0mfz4oNBJrJqZfuZWUOJdmyq/ZcFaB+YF8GucmUKMncSlZoAozwwOjAMBgNV"
    "HRMEBTADAQH/MBUGA1UdJQQOMAwGCisGAQQBgt58AQEwEwYDVR0jBAwwCqAIT9/x"
    "lYHtWkwwCgYIKoZIzj0EAwIDSQAwRgIhAMTyK7btKTjriyM+Z5IoI96VyUnnfLUl"
    "yAI94VWoK1nVAiEAyjWDTZikPwWFG7Ma2IDu3A39LWHYjyhes5xMV7oG44Y="
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBSDCB7qADAgECAgIwMjAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjEwHhcN"
    "MTYwMjA5MDA0ODM0WhcNMTYwMjA5MDMzNTE0WjAOMQwwCgYDVQQDDANjbjIwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAASvUK0iuLHtZjTTqHB9PEtY6iivCckgKEHu"
    "Eat6I/blbiQvNYe5AX8taZD6dVntU8Rs30Ua6nQNSYvFIeUm9wV4ozwwOjAMBgNV"
    "HRMEBTADAQH/MBUGA1UdJQQOMAwGCisGAQQBgt58AQEwEwYDVR0jBAwwCqAIQPGV"
    "somA/vswCgYIKoZIzj0EAwIDSQAwRgIhANMgbRmi3sEmQplB6fRDx9ijrs5yVx30"
    "ayowCW26sKSyAiEAwFTh6CwdAgTAJ4X6Yr2SJ0mGkh6EKILIPvoGyARQPNM="
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBMjCB2aADAgECAgIwMTAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjEwHhcN"
    "MTYwMjA5MDA0ODM0WhcNMTYwMjA5MDMzNTE0WjAOMQwwCgYDVQQDDANjbjEwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAARLrc3K8qbzf5WyHTNHERLFyF5NauTSWOAs"
    "x6lql+DbGfBFeS6G5XL0akNmxJcRLUma6BKnyll9zj6fEpA5dbvaoycwJTAMBgNV"
    "HRMEBTADAQH/MBUGA1UdJQQOMAwGCisGAQQBgt58AQEwCgYIKoZIzj0EAwIDSAAw"
    "RQIgAn13qEfFf3H0MSdvNC/NVgWVBRoJWpZ8IWcC+cf5HqwCIQDSQrb1gop6PeqN"
    "mTMTCVFSHo33KuSn0Y7Dbpc2N3BpvQ=="
    "-----END CERTIFICATE-----"
};

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
    root = AJ_X509DecodeCertificateChainPEM(pem_x509_identity);

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
