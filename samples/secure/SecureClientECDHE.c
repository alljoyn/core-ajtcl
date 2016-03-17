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
#define AJ_MODULE SECURE_CLIENT

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_auth_listener.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_security.h>
#include <ajtcl/aj_authorisation.h>

/*
 * If MAIN_ALLOW_ARGS is defined, the user must specify the auth suite to use.
 * If it's not defined, all auth suites are enabled, and AllJoyn negotiates
 * one to use, and in the event of failure, tries multiple auth suites until
 * one succeeds.
 */
#define MAIN_ALLOW_ARGS

uint8_t dbgSECURE_CLIENT = 0;

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

static const char ServiceName[] = "org.alljoyn.bus.samples.secure";
static const char InterfaceName[] = "org.alljoyn.bus.samples.secure.SecureInterface";
static const char ServicePath[] = "/SecureService";
static const uint16_t ServicePort = 42;

/*
 * Buffer to hold the full service name. This buffer must be big enough to hold
 * a possible 255 characters plus a null terminator (256 bytes)
 */
static char fullServiceName[AJ_MAX_SERVICE_NAME_SIZE];

static const char* const secureInterface[] = {
    "$org.alljoyn.bus.samples.secure.SecureInterface",
    "?Ping inStr<s outStr>s",
    NULL
};

static const AJ_InterfaceDescription secureInterfaces[] = {
    secureInterface,
    NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object ProxyObjects[] = {
    { ServicePath, secureInterfaces },
    { NULL }
};

static AJ_PermissionMember members[] = { { "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_MODIFY | AJ_ACTION_OBSERVE, NULL } };
static AJ_PermissionRule rules[] = { { ServicePath, InterfaceName, members, NULL } };

#define PRX_PING   AJ_PRX_MESSAGE_ID(0, 0, 0)

/*
 * Let the application do some work
 */
static void AppDoWork()
{
}

/*
 * get a line of input from the file pointer (most likely stdin).
 * This will capture the the num-1 characters or till a newline character is
 * entered.
 *
 * @param[out] str a pointer to a character array that will hold the user input
 * @param[in]  num the size of the character array 'str'
 * @param[in]  fp the file pointer the sting will be read from. (most likely stdin)
 *
 * @return returns the length of the string received from the file.
 */
uint32_t get_line(char* str, int num, FILE* fp)
{
    uint32_t stringLength = 0;
    char* p = fgets(str, num, fp);

    // fgets will capture the '\n' character if the string entered is shorter than
    // num. Remove the '\n' from the end of the line and replace it with nul '\0'.
    if (p != NULL) {
        stringLength = (uint32_t)strlen(str) - 1;
        if (str[stringLength] == '\n') {
            str[stringLength] = '\0';
        }
    }

    return stringLength;
}

#define CONNECT_TIMEOUT    (1000 * 200)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (100 * 10)

static char pingString[] = "Client AllJoyn Lite says Hello AllJoyn!";

AJ_Status SendPing(AJ_BusAttachment* bus, uint32_t sessionId)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_Printf("Sending ping request '%s'.\n", pingString);

    status = AJ_MarshalMethodCall(bus,
                                  &msg,
                                  PRX_PING,
                                  fullServiceName,
                                  sessionId,
                                  AJ_FLAG_ENCRYPTED,
                                  METHOD_TIMEOUT);
    if (AJ_OK == status) {
        status = AJ_MarshalArgs(&msg, "s", pingString);
    } else {
        AJ_InfoPrintf(("In SendPing() AJ_MarshalMethodCall() status = %d.\n", status));
    }

    if (AJ_OK == status) {
        status = AJ_DeliverMsg(&msg);
    } else {
        AJ_InfoPrintf(("In SendPing() AJ_MarshalArgs() status = %d.\n", status));
    }

    if (AJ_OK != status) {
        AJ_InfoPrintf(("In SendPing() AJ_DeliverMsg() status = %d.\n", status));
    }

    return status;
}

// Copied from alljoyn/alljoyn_core/unit_test/AuthListenerECDHETest.cc with
// newlines removed

static const char pem_prv[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MDECAQEEIMtCXTgmP+mWy/R3r+xhRVz28c7Mg/3/rFozWEngZIEmoAoGCCqGSM49AwEH"
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBRDCB66ADAgECAgIwMjAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjEwHhcN"
    "MTYwMzE3MjIxNjI4WhcNMTYwMzE4MDEwMzA4WjAOMQwwCgYDVQQDDANjbjIwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAASLzhwhsTFYITWYFWjxzsCjeWmmPpBYyphL"
    "B9JjxhGf8hO8jIHyYzVGbwFLo8yxdLi/1aAfygdZAQg4yrgktY7LozkwNzAJBgNV"
    "HRMEAjAAMBUGA1UdJQQOMAwGCisGAQQBgt58AQEwEwYDVR0jBAwwCqAIT3aVgSWQ"
    "cxQwCgYIKoZIzj0EAwIDSAAwRQIgQbIJ8XFFQegKmGlVrrAEDfOajRo6AlR/eDHa"
    "s/9gPH4CIQDxTdT7JSsskcSlfv3iPj4QEQMAyBCoClDTxtB76y3O8g=="
    "-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----"
    "MIIBMjCB2aADAgECAgIwMTAKBggqhkjOPQQDAjAOMQwwCgYDVQQDDANjbjEwHhcN"
    "MTYwMzE3MjIxNjI4WhcNMTYwMzE4MDEwMzA4WjAOMQwwCgYDVQQDDANjbjEwWTAT"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAARN2kDX85eo+La+shs813nyoF4s6zEBDBop"
    "37Od5JjxyjznaqjZAja35ArHFiyIiW6MHIsOe/Lh1eH+DobTdmjioycwJTAMBgNV"
    "HRMEBTADAQH/MBUGA1UdJQQOMAwGCisGAQQBgt58AQEwCgYIKoZIzj0EAwIDSAAw"
    "RQIgC+/FJEGmD72oTE8mr+nb+LCS9rbvdzHiGgeFw1fiKYYCIQDEwvNzqtcgoaFK"
    "AWcekk3QYgDKwrwJVmwbxuHT8etlxw=="
    "-----END CERTIFICATE-----"
};

// Security 1.0 certificates without EKUs
static const char pem_prv_noekus[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MDECAQEEINAmL3v0wNo5EfMqzB/GiVturVDGGefg9bPY/rZ5cM1GoAoGCCqGSM49"
    "AwEH"
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509_noekus[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBajCCARCgAwIBAgIUYB6roPAvFLNLCDrHmQB+pD8LjbkwCgYIKoZIzj0EAwIw"
    "NTEzMDEGA1UEAwwqQWxsSm95biBFQ0RIRSBTYW1wbGUgQ2VydGlmaWNhdGUgQXV0"
    "aG9yaXR5MB4XDTE1MDUwNzIyMTY0NVoXDTIwMDUwNTIyMTY0NVowJjEkMCIGA1UE"
    "AwwbQWxsSm95biBFQ0RIRSBTYW1wbGUgQ2xpZW50MFkwEwYHKoZIzj0CAQYIKoZI"
    "zj0DAQcDQgAEzE6Fox8LU/Cbi9+KI+6wQsFA8RhOv44JxTa1PY13xQGgzL0h+KKq"
    "DrHleThtYqL8rFXFtuDMtYo1T/lOMIcz86MNMAswCQYDVR0TBAIwADAKBggqhkjO"
    "PQQDAgNIADBFAiEA3KmONKSK9ebMUnBxDTYZMilW1QNqyR04KB3TUuI1MvcCIDTZ"
    "MzxxFqMIDDaGUzqd4g1t/W9h+G+alwj3KemLkD3T"
    "-----END CERTIFICATE-----"
    ""
    "-----BEGIN CERTIFICATE-----"
    "MIIBezCCASKgAwIBAgIUDrFhHE80+zbEUOCNTxw219Nd1qwwCgYIKoZIzj0EAwIw"
    "NTEzMDEGA1UEAwwqQWxsSm95biBFQ0RIRSBTYW1wbGUgQ2VydGlmaWNhdGUgQXV0"
    "aG9yaXR5MB4XDTE1MDUwNzIyMTYzNloXDTI1MDUwNDIyMTYzNlowNTEzMDEGA1UE"
    "AwwqQWxsSm95biBFQ0RIRSBTYW1wbGUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MFkw"
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6AsCTTviTBWX0Jw2e8Cs8DhwxfRd37Yp"
    "IH5ALzBqwUN2sfG1odcthe6GKdE/9oVfy12SXOL3X2bi3yg1XFoWnaMQMA4wDAYD"
    "VR0TBAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiASuD0OrpDM8ziC5GzMbZWKNE/X"
    "eboedc0p6YsAZmry2AIgR23cKM4cKkc2bgUDbETNbDcOcwm+EWaK9E4CkOO/tBc="
    "-----END CERTIFICATE-----"
};

static const char psk_hint[] = "<anonymous>";
static const char psk_char[] = "faaa0af3dd3f1e0379da046a3ab6ca44";
static const char ecspeke_password[] = "1234";
static X509CertificateChain* chain = NULL;
static uint8_t noekus = FALSE;

static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential*cred)
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

    case AUTH_SUITE_ECDHE_SPEKE:
        switch (command) {
        case AJ_CRED_PASSWORD:
            cred->data = (uint8_t*)ecspeke_password;
            cred->len = strlen(ecspeke_password);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;
        }
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        switch (command) {
        case AJ_CRED_PRV_KEY:
            AJ_ASSERT(sizeof (AJ_ECCPrivateKey) == cred->len);
            status = AJ_DecodePrivateKeyPEM((AJ_ECCPrivateKey*) cred->data, noekus ? pem_prv_noekus : pem_prv);
            cred->expiration = keyexpiration;
            break;

        case AJ_CRED_CERT_CHAIN:
            switch (cred->direction) {
            case AJ_CRED_REQUEST:
                // Free previous certificate chain
                AJ_X509FreeDecodedCertificateChain(chain);
                chain = AJ_X509DecodeCertificateChainPEM(noekus ? pem_x509_noekus : pem_x509);
                if (NULL == chain) {
                    return AJ_ERR_INVALID;
                }
                cred->data = (uint8_t*) chain;
                cred->expiration = keyexpiration;
                status = AJ_OK;
                break;

            case AJ_CRED_RESPONSE:
                node = (X509CertificateChain*) cred->data;
                status = AJ_X509VerifyChain(node, NULL, AJ_CERTIFICATE_IDN_X509);
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

void AuthCallback(const void* context, AJ_Status status)
{
    *((AJ_Status*)context) = status;
}

#ifdef MAIN_ALLOWS_ARGS
int AJ_Main(int ac, char** av)
#else
int AJ_Main(void)
#endif
{
    int done = FALSE;
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;
    AJ_Status authStatus = AJ_ERR_NULL;
    uint16_t state;
    uint16_t capabilities;
    uint16_t info;

    uint32_t suites[16];
    size_t numsuites = 0;
    uint8_t clearkeys = FALSE;

#ifdef MAIN_ALLOWS_ARGS
    ac--;
    av++;
    /*
     * Enable authentication mechanism by command line
     */
    while (ac) {
        if (0 == strncmp(*av, "-noekus", 7)) {
            noekus = TRUE;
            ac--;
            av++;
        } else if (0 == strncmp(*av, "-e", 2)) {
            if (0 == strncmp(*av, "-ek", 3)) {
                clearkeys = TRUE;
            }
            ac--;
            av++;

            if (!ac) {
                AJ_Printf("-e(k) requires an auth mechanism.\n");
                return 1;
            }
            while (ac) {
                if (0 == strncmp(*av, "ECDHE_ECDSA", 11)) {
                    suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
                } else if (0 == strncmp(*av, "ECDHE_PSK", 9)) {
                    suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
                } else if (0 == strncmp(*av, "ECDHE_NULL", 10)) {
                    suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
                } else if (0 == strncmp(*av, "ECDHE_SPEKE", 11)) {
                    suites[numsuites++] = AUTH_SUITE_ECDHE_SPEKE;
                }
                ac--;
                av++;
            }
        } else {
            AJ_Printf("SecureClientECDHE [-noekus] [-e|-ek] <encryption suites>\n"
                      "-noekus\n"
                      "   For ECDHE_ECDSA, present a Security 1.0-style certificate chain without EKUs\n"
                      "   For all other auth suites, this option has no effect.\n"
                      "-e <encryption suites>\n"
                      "   Specify one or more encryption suites to use: ECDHE_ECDSA, ECDHE_PSK, or ECDHE_NULL\n"
                      "   Encryption suites should be listed in desired order of attempting, separated by spaces.\n"
                      "-ek <encryption suites>\n"
                      "    Same as -e, except that any existing authentication keys are cleared. This \n"
                      "    will ensure a new key exchange occurs.\n"
                      "-e or -ek must be the last option on the command line.\n");
            return AJ_ERR_NULL;
        }
    }
#else
    /*
     * Allow all authentication mechanisms
     */
    AJ_AlwaysPrintf(("Ignoring command line arguments: enabling all auth suites, not clearing the keystore and using EKUs in certificates.\n"));
    clearkeys = FALSE;
    noekus = FALSE;
    suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
    suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
    suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
    suites[numsuites++] = AUTH_SUITE_ECDHE_SPEKE;
#endif

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(ProxyObjects);
    AJ_RegisterObjects(NULL, ProxyObjects);

    while (!done) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartClientByName(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServiceName, ServicePort, &sessionId, NULL, fullServiceName);
            if (status == AJ_OK) {
                AJ_InfoPrintf(("StartClient returned %d, sessionId=%u\n", status, sessionId));
                AJ_Printf("StartClient returned %d, sessionId=%u\n", status, sessionId);
                connected = TRUE;
                AJ_BusEnableSecurity(&bus, suites, numsuites);
                AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
                if (clearkeys) {
                    status = AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
                    if (AJ_OK != status) {
                        AJ_Printf("AJ_ClearCredentials returned %d\n", status);
                        break;
                    }
                }
                AJ_ManifestTemplateSet(rules);
                AJ_SecurityGetClaimConfig(&state, &capabilities, &info);
                /* Set app claimable if not already claimed */
                if (APP_STATE_CLAIMED != state) {
                    AJ_SecuritySetClaimConfig(&bus, APP_STATE_CLAIMABLE, CLAIM_CAPABILITY_ECDHE_PSK, 0);
                }

                status = AJ_BusAuthenticatePeer(&bus, fullServiceName, AuthCallback, &authStatus);
                if (status != AJ_OK) {
                    AJ_Printf("AJ_BusAuthenticatePeer returned %d\n", status);
                    break;
                }
            } else {
                AJ_InfoPrintf(("StartClient returned %d\n", status));
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
            status = SendPing(&bus, sessionId);
            if (status != AJ_OK) {
                AJ_Printf("SendPing returned %d\n", status);
                continue;
            }
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            AppDoWork();
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_REPLY_ID(PRX_PING):
                {
                    AJ_Arg arg;

                    if (AJ_OK == AJ_UnmarshalArg(&msg, &arg)) {
                        AJ_Printf("%s.Ping (path=%s) returned \"%s\".\n", InterfaceName,
                                  ServicePath, arg.val.v_string);

                        if (strcmp(arg.val.v_string, pingString) == 0) {
                            AJ_InfoPrintf(("Ping was successful.\n"));
                        } else {
                            AJ_InfoPrintf(("Ping returned different string.\n"));
                        }
                    } else {
                        AJ_ErrPrintf(("Bad ping response.\n"));
                    }
                    done = TRUE;
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /*
                 * Force a disconnect
                 */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u", id, reason));
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

        if ((status == AJ_ERR_READ) || (status == AJ_ERR_WRITE)) {
            AJ_Printf("AllJoyn disconnect.\n");
            AJ_Disconnect(&bus);
            break;
        }
    }

    AJ_Printf("SecureClient EXIT %d.\n", status);

    // Clean up certificate chain
    AJ_X509FreeDecodedCertificateChain(chain);
    return status;
}

#ifdef AJ_MAIN
#ifdef MAIN_ALLOWS_ARGS
int main(int ac, char** av)
{
    return AJ_Main(ac, av);
}
#else
int main(void)
{
    return AJ_Main();
}
#endif
#endif
