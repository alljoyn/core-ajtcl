/**
 * @file
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#define AJ_MODULE SECURE_SERVICE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_auth_listener.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_security.h>
#include <ajtcl/aj_authorisation.h>

uint8_t dbgSECURE_SERVICE = 1;

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

#define CONNECT_ATTEMPTS   10
static const char s_serviceName[] = "org.alljoyn.bus.samples.secure";
static const char s_interfaceName[] = "org.alljoyn.bus.samples.secure.SecureInterface";
static const char s_servicePath[] = "/SecureService";
static const uint16_t s_servicePort = 42;
static AJ_BusAttachment s_bus;
static uint8_t s_connected = FALSE;

/**
 * The interface name followed by the method signatures.
 *
 * See also .\inc\aj_introspect.h
 */
static const char* const s_secureInterface[] = {
    "$org.alljoyn.bus.samples.secure.SecureInterface",
    "?Ping inStr<s outStr>s",  /* Method at index 0. */
    NULL
};

/**
 * A NULL terminated collection of all interfaces.
 */
static const AJ_InterfaceDescription s_secureInterfaces[] = {
    s_secureInterface,
    NULL
};

/**
 * Objects implemented by the application. The first member in the AJ_Object structure is the path.
 * The second is the collection of all interfaces at that path.
 */
static const AJ_Object s_appObjects[] = {
    { s_servicePath, s_secureInterfaces },
    { NULL }
};

static AJ_PermissionMember s_members[] = { { "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_PROVIDE | AJ_ACTION_OBSERVE, NULL } };
static AJ_PermissionRule s_rules[] = { { s_servicePath, s_interfaceName, PRIVILEGED, s_members, NULL } };

/*
 * The value of the arguments are the indices of the
 * object path in s_appObjects (above), interface in sampleInterfaces (above), and
 * member indices in the interface.
 * The 'ping' index is 0 because the first entry in sampleInterface is the interface name.
 * This makes the first index (index 0 of the methods) the second string in
 * s_secureInterfaces[].
 *
 * See also .\inc\aj_introspect.h
 */
#define BASIC_SERVICE_PING AJ_APP_MESSAGE_ID(0, 0, 0)

static AJ_Status AppHandlePing(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message reply;
    AJ_Arg arg;

    status = AJ_UnmarshalArg(msg, &arg);

    if (AJ_OK == status) {

        if (arg.typeId == AJ_ARG_STRING) {
            AJ_Printf("Received ping request '%s'.\n", arg.val.v_string);
        } else {
            AJ_Printf("Unexpected arg type '%d' in ping request.\n", arg.typeId);
        }

        status = AJ_MarshalReplyMsg(msg, &reply);

        if (AJ_OK == status) {
            /*
             * Just return the arg we received
             */
            status = AJ_MarshalArg(&reply, &arg);

            if (AJ_OK == status) {
                status = AJ_DeliverMsg(&reply);
            }
        }
    }

    return status;
}

// Copied from alljoyn/alljoyn_core/unit_test/AuthListenerECDHETest.cc with
// newlines removed
static const char s_pem_prv[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MDECAQEEICCRJMbxSiWUqj4Zs7jFQRXDJdBRPWX6fIVqE1BaXd08oAoGCCqGSM49"
    "AwEH"
    "-----END EC PRIVATE KEY-----"
};

static const char s_pem_x509[] = {
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

static const char s_psk_hint[] = "<anonymous>";
static const char s_psk_char[] = "faaa0af3dd3f1e0379da046a3ab6ca44";
static const char s_ecspeke_password[] = "1234";
static X509CertificateChain* s_chain = NULL;
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

    case AUTH_SUITE_ECDHE_SPEKE:
        switch (command) {
        case AJ_CRED_PASSWORD:
            cred->data = (uint8_t*)s_ecspeke_password;
            cred->len = strlen(s_ecspeke_password);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;
        }
        break;

    /*
     * The ECDHE_PSK auth mechanism is deprecated as of 16.04 and ECDHE_SPEKE
     * should be used instead.
     */
    case AUTH_SUITE_ECDHE_PSK:
        switch (command) {
        case AJ_CRED_PUB_KEY:
            cred->data = (uint8_t*) s_psk_hint;
            cred->len = strlen(s_psk_hint);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;

        case AJ_CRED_PRV_KEY:
            cred->data = (uint8_t*) s_psk_char;
            cred->len = strlen(s_psk_char);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;
        }
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        switch (command) {
        case AJ_CRED_PRV_KEY:
            AJ_ASSERT(sizeof (AJ_ECCPrivateKey) == cred->len);
            status = AJ_DecodePrivateKeyPEM((AJ_ECCPrivateKey*) cred->data, s_pem_prv);
            cred->expiration = keyexpiration;
            break;

        case AJ_CRED_CERT_CHAIN:
            switch (cred->direction) {
            case AJ_CRED_REQUEST:
                // Free previous certificate chain
                AJ_X509FreeDecodedCertificateChain(s_chain);
                s_chain = AJ_X509DecodeCertificateChainPEM(s_pem_x509);
                if (NULL == s_chain) {
                    return AJ_ERR_INVALID;
                }
                cred->data = (uint8_t*) s_chain;
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

static const uint32_t s_suites[4] = { AUTH_SUITE_ECDHE_ECDSA, AUTH_SUITE_ECDHE_SPEKE, AUTH_SUITE_ECDHE_PSK, AUTH_SUITE_ECDHE_NULL };
static const size_t s_numsuites = 4;

/* All times are expressed in milliseconds. */
#define CONNECT_TIMEOUT     (1000 * 60)
#define SLEEP_TIME          (1000 * 2)

/* SIGINT signal handler. */
static void SigIntHandler(int sig)
{
    ((void)(sig));
    if (s_connected) {
        AJ_Disconnect(&s_bus);
    }
    AJ_X509FreeDecodedCertificateChain(s_chain);
    AJ_AlwaysPrintf(("\nSecureServiceECDHE exiting after SIGINT (OK)\n"));
    exit(0);
}

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    uint32_t sessionId = 0;
    uint16_t state;
    uint16_t capabilities;
    uint16_t info;

    /* Install SIGINT handler. */
    signal(SIGINT, SigIntHandler);

    /* One time initialization before calling any other AllJoyn APIs. */
    AJ_Initialize();

    /* This is for debug purposes and is optional. */
    AJ_PrintXML(s_appObjects);
    AJ_RegisterObjects(s_appObjects, NULL);

    while (TRUE) {
        AJ_Message msg;

        if (!s_connected) {
            status = AJ_StartService(&s_bus,
                                     NULL,
                                     CONNECT_TIMEOUT,
                                     FALSE,
                                     s_servicePort,
                                     s_serviceName,
                                     AJ_NAME_REQ_DO_NOT_QUEUE,
                                     NULL);

            if (status != AJ_OK) {
                continue;
            }

            AJ_InfoPrintf(("StartService returned %d, session_id=%u\n", status, sessionId));
            s_connected = TRUE;

            AJ_BusEnableSecurity(&s_bus, s_suites, s_numsuites);
            AJ_BusSetAuthListenerCallback(&s_bus, AuthListenerCallback);
            AJ_ManifestTemplateSet(s_rules);
            AJ_SecurityGetClaimConfig(&state, &capabilities, &info);
            /* Set app claimable if not already claimed */
            if (APP_STATE_CLAIMED != state) {
                AJ_SecuritySetClaimConfig(&s_bus, APP_STATE_CLAIMABLE, CLAIM_CAPABILITY_ECDHE_PSK, 0);
            }
        }

        status = AJ_UnmarshalMsg(&s_bus, &msg, AJ_UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    if (port == s_servicePort) {
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

            case BASIC_SERVICE_PING:
                status = AppHandlePing(&msg);
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /* Force a disconnect. */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u", id, reason));
                }
                status = AJ_ERR_SESSION_LOST;
                break;

            default:
                /* Pass to the built-in handlers. */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }

        /* Messages MUST be discarded to free resources. */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_READ) || (status == AJ_ERR_WRITE)) {
            AJ_Printf("AllJoyn disconnect.\n");
            AJ_Disconnect(&s_bus);
            s_connected = FALSE;

            /* Sleep a little while before trying to reconnect. */
            AJ_Sleep(SLEEP_TIME);
        }
    }

    AJ_Printf("Secure service exiting with status 0x%04x.\n", status);

    // Clean up certificate chain
    AJ_X509FreeDecodedCertificateChain(s_chain);
    return status;
}

#ifdef AJ_MAIN
int main(void)
{
    return AJ_Main();
}
#endif
