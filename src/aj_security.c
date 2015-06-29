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
#define AJ_MODULE SECURITY

#include "aj_authorisation.h"
#include "aj_target.h"
#include "aj_security.h"
#include "aj_std.h"
#include "aj_debug.h"
#include "aj_peer.h"
#include "aj_crypto_ecc.h"
#include "aj_guid.h"
#include "aj_cert.h"
#include "aj_config.h"
#include "aj_crypto.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgSECURITY = 0;
#endif

#define APPLICATION_VERSION                    1
#define SECURITY_APPLICATION_VERSION           1
#define SECURITY_CLAIMABLE_APPLICATION_VERSION 1
#define SECURITY_MANAGED_APPLICATION_VERSION   1

#define PUBLICKEY_ALG_ECDSA_SHA256             0
#define PUBLICKEY_CRV_NISTP256                 0
#define DIGEST_ALG_SHA256                      0

static uint8_t emit = FALSE;
static uint16_t claimState = APP_STATE_NOT_CLAIMABLE;
static uint16_t claimCapabilities = 0;
static uint16_t claimInfo = 0;

typedef struct _CertificateId {
    DER_Element serial;    /**< Certificate serial number */
    DER_Element aki;       /**< Certificate issuer aki */
    AJ_ECCPublicKey pub;   /**< Certificate issuer public key */
} CertificateId;

static AJ_Status SetClaimState(uint16_t state)
{
    AJ_Status status;
    AJ_CredField data;

    data.size = sizeof (uint16_t);
    data.data = (uint8_t*) &state;

    status = AJ_CredentialSet(AJ_CONFIG_CLAIMSTATE | AJ_CRED_TYPE_CONFIG, NULL, 0xFFFFFFFF, &data);

    return status;
}

static AJ_Status GetClaimState(uint16_t* state)
{
    AJ_Status status;
    AJ_CredField data;

    /* Default to not claimable, in case of error */
    *state = APP_STATE_NOT_CLAIMABLE;

    data.size = sizeof (uint16_t);
    data.data = (uint8_t*) state;
    status = AJ_CredentialGet(AJ_CONFIG_CLAIMSTATE | AJ_CRED_TYPE_CONFIG, NULL, NULL, &data);

    return status;
}

void AJ_SecuritySetClaimConfig(uint16_t state, uint16_t capabilities, uint16_t info)
{
    claimState = state;
    claimCapabilities = capabilities;
    claimInfo = info;
    SetClaimState(state);
}

void AJ_SecurityGetClaimConfig(uint16_t* state, uint16_t* capabilities, uint16_t* info)
{
    *state = claimState;
    *capabilities = claimCapabilities;
    *info = claimInfo;
}

AJ_Status AJ_SecurityInit(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_ECCPublicKey pub;
    AJ_ECCPrivateKey prv;
    uint8_t bound = FALSE;

    AJ_InfoPrintf(("AJ_SecurityInit(bus=%p)\n", bus));

    /* Check I have a key pair */
    status = AJ_CredentialGetECCPublicKey(AJ_ECC_SIG, NULL, NULL, NULL);
    if (AJ_OK != status) {
        /* Generate my communication signing key */
        status = AJ_GenerateECCKeyPair(&pub, &prv);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_CredentialSetECCPublicKey(AJ_ECC_SIG, NULL, 0xFFFFFFFF, &pub);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_CredentialSetECCPrivateKey(AJ_ECC_SIG, NULL, 0xFFFFFFFF, &prv);
        if (AJ_OK != status) {
            return status;
        }
    }

    /*
     * Bind to the security management port
     */
    AJ_InfoPrintf(("AJ_SecurityInit(bus=%p): Bind Session Port %d\n", bus, AJ_SECURE_MGMT_PORT));
    status = AJ_BusBindSessionPort(bus, AJ_SECURE_MGMT_PORT, NULL, 0);
    if (AJ_OK != status) {
        return status;
    }
    while (!bound && (AJ_OK == status)) {
        AJ_Message msg;
        status = AJ_UnmarshalMsg(bus, &msg, AJ_UNMARSHAL_TIMEOUT);
        if (AJ_ERR_NO_MATCH == status) {
            status = AJ_OK;
            continue;
        }
        if (AJ_OK != status) {
            break;
        }
        switch (msg.msgId) {
        case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
            if (msg.hdr->msgType == AJ_MSG_ERROR) {
                AJ_ErrPrintf(("AJ_SecurityInit(bus=%p): AJ_METHOD_BIND_SESSION_PORT: %s\n", bus, msg.error));
                status = AJ_ERR_FAILURE;
            } else {
                AJ_InfoPrintf(("AJ_SecurityInit(bus=%p): AJ_METHOD_BIND_SESSION_PORT: OK\n", bus));
                bound = TRUE;
            }
            break;

        default:
            /*
             * Pass to the built-in bus message handlers
             */
            status = AJ_BusHandleBusMessage(&msg);
            break;
        }
        AJ_CloseMsg(&msg);
    }

    /* Get the initial claim state */
    GetClaimState(&claimState);

    AJ_AuthorisationInit();

    emit = TRUE;

    return AJ_ApplicationStateSignal(bus);
}

AJ_Status AJ_UnmarshalECCPublicKey(AJ_Message* msg, AJ_ECCPublicKey* pub)
{
    AJ_Status status = AJ_OK;
    uint8_t* x;
    uint8_t* y;
    size_t xlen;
    size_t ylen;

    /* Unmarshal key */
    status = AJ_UnmarshalArgs(msg, "(yyayay)", &pub->alg, &pub->crv, &x, &xlen, &y, &ylen);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (PUBLICKEY_ALG_ECDSA_SHA256 != pub->alg) {
        goto Exit;
    }
    if (PUBLICKEY_CRV_NISTP256 != pub->crv) {
        goto Exit;
    }
    if ((KEY_ECC_SZ != xlen) || (KEY_ECC_SZ != ylen)) {
        goto Exit;
    }
    memcpy(pub->x, x, KEY_ECC_SZ);
    memcpy(pub->y, y, KEY_ECC_SZ);

    return AJ_OK;

Exit:
    return AJ_ERR_INVALID;
}

static AJ_Status GetCertificateId(CertificateId* certificateId, AJ_CredField* field, uint16_t type)
{
    AJ_Status status;
    AJ_MsgHeader hdr;
    AJ_Message msg;
    AJ_BusAttachment bus;
    DER_Element der;
    X509Certificate certificate;
    AJ_Arg container;
    uint8_t alg;
    AJ_CredField id;

    AJ_LocalMsg(&bus, &hdr, &msg, "a(yay)", field->data, field->size);

    /**
     * Serial number is in the first certificate
     * Authority AKI is in the last certificate
     * Authority PublicKey is in the keystore
     */
    memset(certificateId, 0, sizeof (CertificateId));
    status = AJ_UnmarshalContainer(&msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalArgs(&msg, "(yay)", &alg, &der.data, &der.size);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_X509DecodeCertificateDER(&certificate, &der);
        if (AJ_OK != status) {
            return status;
        }
        if (NULL == certificateId->serial.data) {
            certificateId->serial.size = certificate.tbs.serial.size;
            certificateId->serial.data = certificate.tbs.serial.data;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(&msg, &container);
    if (AJ_OK != status) {
        return status;
    }
    certificateId->aki.size = certificate.tbs.extensions.aki.size;
    certificateId->aki.data = certificate.tbs.extensions.aki.data;
    id.size = certificateId->aki.size;
    id.data = certificateId->aki.data;
    status = AJ_CredentialGetECCPublicKey(type, &id, NULL, &certificateId->pub);

    return status;
}

static AJ_Status SetDefaultPolicy(AJ_ECCPublicKey* pub, uint8_t* g, size_t glen)
{
    AJ_Status status;
    AJ_BusAttachment tmp;
    AJ_MsgHeader hdr;
    AJ_Message msg;
    AJ_CredField data;
    uint8_t* buf = NULL;
    size_t len;

    /* Create a marshalled policy message - 256 bytes should be sufficient */
    len = 256;
    buf = AJ_Malloc(len);
    if (NULL == buf) {
        goto Exit;
    }
    AJ_LocalMsg(&tmp, &hdr, &msg, "(qua(a(ya(yyayay)ay)a(ssa(syy))))", buf, len);
    data.data = tmp.sock.tx.writePtr;
    status = AJ_MarshalDefaultPolicy(&msg, pub, g, glen);
    if (AJ_OK != status) {
        goto Exit;
    }
    data.size = tmp.sock.tx.writePtr - data.data;
    /* Store the policy */
    status = AJ_CredentialSet(AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &data);

Exit:
    AJ_Free(buf);
    return status;
}

//SIG = a(ayayyyayay)
static AJ_Status MarshalMembershipIds(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    AJ_CredField data;
    CertificateId certificate;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;

    data.data = NULL;
    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        data.data = NULL;
        status = AJ_CredentialGetNext(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &data, &slot);
        slot++;
        if (AJ_OK == status) {
            status = GetCertificateId(&certificate, &data, AJ_ECC_CA_ADMIN);
            if (AJ_OK != status) {
                goto Exit;
            }
            status = AJ_MarshalArgs(msg, "(ayayyyayay)",
                                    certificate.serial.data, certificate.serial.size,
                                    certificate.aki.data, certificate.aki.size,
                                    certificate.pub.alg, certificate.pub.crv,
                                    certificate.pub.x, KEY_ECC_SZ, certificate.pub.y, KEY_ECC_SZ);
            if (AJ_OK != status) {
                goto Exit;
            }
        }
        AJ_CredFieldFree(&data);
    }

    status = AJ_MarshalCloseContainer(msg, &container);
    return status;

Exit:
    AJ_CredFieldFree(&data);
    return status;
}

/*
 * org.alljoyn.Bus.Application implementation
 */
static AJ_Status ApplicationGetProperty(AJ_Message* reply, uint32_t id, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;

    switch (id) {
    case AJ_PROPERTY_APPLICATION_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) APPLICATION_VERSION);
        break;

    default:
        status = AJ_ERR_UNEXPECTED;
        break;
    }

    return status;
}

AJ_Status AJ_ApplicationGetProperty(AJ_Message* msg)
{
    return AJ_BusPropGet(msg, ApplicationGetProperty, NULL);
}

AJ_Status AJ_ApplicationStateSignal(AJ_BusAttachment* bus)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_ECCPublicKey pub;

    if (!emit) {
        return AJ_OK;
    }
    emit = FALSE;

    AJ_InfoPrintf(("AJ_ApplicationStateSignal(bus=%p)\n", bus));

    status = AJ_MarshalSignal(bus, &msg, AJ_SIGNAL_APPLICATION_STATE, NULL, 0, ALLJOYN_FLAG_SESSIONLESS, 0);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_CredentialGetECCPublicKey(AJ_ECC_SIG, NULL, NULL, &pub);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(&msg, "(yyayay)", pub.alg, pub.crv, pub.x, sizeof (pub.x), pub.y, sizeof (pub.y));
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(&msg, "q", claimState);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_DeliverMsg(&msg);

    return status;
}

/*
 * org.alljoyn.Bus.Security.Application implementation
 */
static AJ_Status SecurityGetProperty(AJ_Message* reply, uint32_t id, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;
    CertificateId certificate;
    AJ_CredField field;
    AJ_ECCPublicKey pub;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint32_t version;

    field.data = NULL;
    field.size = 0;

    switch (id) {
    case AJ_PROPERTY_SEC_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) SECURITY_APPLICATION_VERSION);
        break;

    case AJ_PROPERTY_SEC_APPLICATION_STATE:
        status = AJ_MarshalArgs(reply, "q", claimState);
        break;

    case AJ_PROPERTY_SEC_MANIFEST_DIGEST:
        status = AJ_CredentialGet(AJ_CRED_TYPE_MANIFEST, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        AJ_ManifestDigest(&field, digest);
        status = AJ_MarshalArgs(reply, "(yay)", DIGEST_ALG_SHA256, digest, SHA256_DIGEST_LENGTH);
        break;

    case AJ_PROPERTY_SEC_ECC_PUBLICKEY:
        status = AJ_CredentialGetECCPublicKey(AJ_ECC_SIG, NULL, NULL, &pub);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalArgs(reply, "(yyayay)", pub.alg, pub.crv, pub.x, sizeof (pub.x), pub.y, sizeof (pub.y));
        break;

    case AJ_PROPERTY_SEC_MANUFACTURER_CERTIFICATE:
        status = AJ_CredentialGet(AJ_CERTIFICATE_OEM_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_SetMsgBody(reply, 'a', field.data, field.size);
        break;

    case AJ_PROPERTY_SEC_MANIFEST_TEMPLATE:
        status = AJ_ManifestTemplateMarshal(reply);
        break;

    case AJ_PROPERTY_SEC_CLAIM_CAPABILITIES:
        status = AJ_MarshalArgs(reply, "q", claimCapabilities);
        break;

    case AJ_PROPERTY_SEC_CLAIM_CAPABILITIES_INFO:
        status = AJ_MarshalArgs(reply, "q", claimInfo);
        break;

    case AJ_PROPERTY_CLAIMABLE_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) SECURITY_CLAIMABLE_APPLICATION_VERSION);
        break;

    case AJ_PROPERTY_MANAGED_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) SECURITY_MANAGED_APPLICATION_VERSION);
        break;

    case AJ_PROPERTY_MANAGED_IDENTITY:
        status = AJ_CredentialGet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_SetMsgBody(reply, 'a', field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_MANIFEST:
        status = AJ_CredentialGet(AJ_CRED_TYPE_MANIFEST, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_SetMsgBody(reply, 'a', field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_IDENTITY_CERT_ID:
        status = AJ_CredentialGet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = GetCertificateId(&certificate, &field, AJ_ECC_CA);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalArgs(reply, "(ayayyyayay)",
                                certificate.serial.data, certificate.serial.size,
                                certificate.aki.data, certificate.aki.size,
                                certificate.pub.alg, certificate.pub.crv,
                                certificate.pub.x, KEY_ECC_SZ, certificate.pub.y, KEY_ECC_SZ);
        break;

    case AJ_PROPERTY_MANAGED_POLICY_VERSION:
        status = AJ_PolicyVersion(&version);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalArgs(reply, "u", version);
        break;

    case AJ_PROPERTY_MANAGED_POLICY:
        status = AJ_CredentialGet(AJ_CRED_TYPE_POLICY, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_SetMsgBody(reply, '(', field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_DEFAULT_POLICY:
        status = AJ_CredentialGet(AJ_CONFIG_ADMIN_GROUP | AJ_CRED_TYPE_CONFIG, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_CredentialGetECCPublicKey(AJ_ECC_CA_ADMIN, NULL, NULL, &pub);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalDefaultPolicy(reply, &pub, field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_MEMBERSHIP_SUMMARY:
        status = MarshalMembershipIds(reply);
        break;

    default:
        status = AJ_ERR_UNEXPECTED;
        break;
    }

    AJ_CredFieldFree(&field);
    return status;
}

AJ_Status AJ_SecurityGetProperty(AJ_Message* msg)
{
    return AJ_BusPropGet(msg, SecurityGetProperty, NULL);
}

/*
 * org.alljoyn.Bus.Security.ClaimableApplication implementation
 */
AJ_Status AJ_SecurityClaimMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;
    AJ_CredField id;
    AJ_CredField data;
    AJ_ECCPublicKey pub;
    uint8_t* g;
    size_t glen;

    AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p)\n", msg, reply));

    if (APP_STATE_CLAIMABLE != claimState) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
    }

    /* Unmarshal certificate authority */
    status = AJ_UnmarshalECCPublicKey(msg, &pub);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Unmarshal certificate authority identifier */
    status = AJ_UnmarshalArgs(msg, "ay", &id.data, &id.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store the certificate authority */
    status = AJ_CredentialSetECCPublicKey(AJ_ECC_CA, &id, 0xFFFFFFFF, &pub);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Unmarshal admin group guid */
    status = AJ_UnmarshalArgs(msg, "ay", &g, &glen);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store the admin group guid */
    data.size = glen;
    data.data = g;
    status = AJ_CredentialSet(AJ_CONFIG_ADMIN_GROUP | AJ_CRED_TYPE_CONFIG, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Unmarshal admin certificate authority */
    status = AJ_UnmarshalECCPublicKey(msg, &pub);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Unmarshal admin certificate authority identifier */
    status = AJ_UnmarshalArgs(msg, "ay", &id.data, &id.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store the admin certificate authority */
    status = AJ_CredentialSetECCPublicKey(AJ_ECC_CA_ADMIN, &id, 0xFFFFFFFF, &pub);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get identity certificate */
    status = AJ_GetMsgBody(msg, 'a', &data.data, &data.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store identity certificate as raw marshalled body */
    status = AJ_CredentialSet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get manifest */
    status = AJ_GetMsgBody(msg, 'a', &data.data, &data.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store manifest as raw marshalled body */
    status = AJ_CredentialSet(AJ_CRED_TYPE_MANIFEST, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Set default policy */
    status = SetDefaultPolicy(&pub, g, glen);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Clear master secrets */
    status = AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        return status;
    }
    /* Cannot clear session keys because we are currently in one */

    /* Set claim state and save to nvram */
    claimState = APP_STATE_CLAIMED;
    status = SetClaimState(APP_STATE_CLAIMED);

    /* Claim state changed, emit signal */
    emit = TRUE;

    return status;

Exit:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

/*
 * org.alljoyn.Bus.Security.ManagedApplication implementation
 */
AJ_Status AJ_SecurityResetMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_SecurityResetMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_ClearCredentials(0);
    if (AJ_OK != status) {
        return status;
    }

    status = AJ_MarshalReplyMsg(msg, reply);

    return status;
}

AJ_Status AJ_SecurityUpdateIdentityMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredField data;

    AJ_InfoPrintf(("AJ_SecurityUpdateIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Get identity certificate */
    status = AJ_GetMsgBody(msg, 'a', &data.data, &data.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store identity certificate as raw marshalled body */
    status = AJ_CredentialSet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get manifest */
    status = AJ_GetMsgBody(msg, 'a', &data.data, &data.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store manifest as raw marshalled body */
    status = AJ_CredentialSet(AJ_CRED_TYPE_MANIFEST, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_MarshalReplyMsg(msg, reply);

    return status;

Exit:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityUpdatePolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredField data;

    AJ_InfoPrintf(("AJ_SecurityUpdatePolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Get policy */
    status = AJ_GetMsgBody(msg, '(', &data.data, &data.size);
    if (AJ_OK != status) {
        return status;
    }
    /* Store policy as raw marshalled body */
    status = AJ_CredentialSet(AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        return status;
    }
    /* Clear master secrets */
    status = AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        return status;
    }
    /* Clear session keys */
    AJ_GUID_ClearNameMap();

    status = AJ_MarshalReplyMsg(msg, reply);

    return status;
}

AJ_Status AJ_SecurityResetPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_SecurityResetPolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Delete policy */
    status = AJ_CredentialDelete(AJ_CRED_TYPE_POLICY, NULL);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
    }
    /* Clear master secrets */
    status = AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        return status;
    }
    /* Clear session keys */
    AJ_GUID_ClearNameMap();

    status = AJ_MarshalReplyMsg(msg, reply);

    return status;
}

AJ_Status AJ_SecurityInstallMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredField id;
    AJ_CredField data;
    CertificateId certificate;
    uint8_t* tmp;

    AJ_InfoPrintf(("AJ_SecurityInstallMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    id.size = 0;
    id.data = NULL;

    /* Get membership certificate */
    status = AJ_GetMsgBody(msg, 'a', &data.data, &data.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = GetCertificateId(&certificate, &data, AJ_ECC_CA_ADMIN);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_SecurityInstallMembershipMethod(msg=%p, reply=%p): Certificate Id not valid\n", msg, reply));
        goto Exit;
    }
    /* Store membership certificate */
    id.size = certificate.serial.size + certificate.aki.size + sizeof (AJ_ECCPublicKey);
    id.data = AJ_Malloc(id.size);
    if (NULL == id.data) {
        goto Exit;
    }
    tmp = id.data;
    memcpy(tmp, certificate.serial.data, certificate.serial.size);
    tmp += certificate.serial.size;
    memcpy(tmp, certificate.aki.data, certificate.aki.size);
    tmp += certificate.aki.size;
    memcpy(tmp, (uint8_t*) &certificate.pub, sizeof (AJ_ECCPublicKey));
    status = AJ_CredentialSet(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, &id, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    AJ_CredFieldFree(&id);
    return AJ_MarshalReplyMsg(msg, reply);

Exit:
    AJ_CredFieldFree(&id);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityRemoveMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredField id;
    CertificateId certificate;
    uint8_t* x;
    uint8_t* y;
    size_t xlen;
    size_t ylen;
    uint8_t* tmp;

    AJ_InfoPrintf(("AJ_SecurityRemoveMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    id.size = 0;
    id.data = NULL;

    status = AJ_UnmarshalArgs(reply, "(ayayyyayay)",
                              &certificate.serial.data, &certificate.serial.size,
                              &certificate.aki.data, &certificate.aki.size,
                              &certificate.pub.alg, &certificate.pub.crv,
                              &x, &xlen, &y, &ylen);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (PUBLICKEY_ALG_ECDSA_SHA256 != certificate.pub.alg) {
        goto Exit;
    }
    if (PUBLICKEY_CRV_NISTP256 != certificate.pub.crv) {
        goto Exit;
    }
    if ((KEY_ECC_SZ != xlen) || (KEY_ECC_SZ != ylen)) {
        goto Exit;
    }
    memcpy(certificate.pub.x, x, KEY_ECC_SZ);
    memcpy(certificate.pub.y, y, KEY_ECC_SZ);

    /* Delete membership certificate */
    id.size = certificate.serial.size + certificate.aki.size + sizeof (AJ_ECCPublicKey);
    id.data = AJ_Malloc(id.size);
    if (NULL == id.data) {
        goto Exit;
    }
    tmp = id.data;
    memcpy(tmp, certificate.serial.data, certificate.serial.size);
    tmp += certificate.serial.size;
    memcpy(tmp, certificate.aki.data, certificate.aki.size);
    tmp += certificate.aki.size;
    memcpy(tmp, (uint8_t*) &certificate.pub, sizeof (AJ_ECCPublicKey));
    status = AJ_CredentialDelete(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, &id);
    if (AJ_OK != status) {
        goto Exit;
    }

    AJ_CredFieldFree(&id);
    return AJ_MarshalReplyMsg(msg, reply);

Exit:
    AJ_CredFieldFree(&id);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}
