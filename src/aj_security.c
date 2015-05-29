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

#include "aj_config.h"
#include "aj_creds.h"
#include "aj_security.h"
#include "aj_std.h"
#include "aj_target.h"

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
}

AJ_Status AJ_SecurityInit(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_ECCPublicKey pub;
    AJ_ECCPrivateKey prv;
    uint8_t bound = FALSE;

    AJ_InfoPrintf(("AJ_SecurityInit()\n"));

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
    AJ_InfoPrintf(("AJ_SecurityInit(): Bind Session Port %d\n", AJ_SECURE_MGMT_PORT));
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
                AJ_ErrPrintf(("AJ_SecurityInit(): AJ_METHOD_BIND_SESSION_PORT: %s\n", msg.error));
                status = AJ_ERR_FAILURE;
            } else {
                AJ_InfoPrintf(("AJ_SecurityInit(): AJ_METHOD_BIND_SESSION_PORT: OK\n"));
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

    if (AJ_OK == status) {
        emit = TRUE;
    }

    return status;
}

static AJ_Status UnmarshalECCPublicKey(AJ_Message* msg, AJ_CredField* id, AJ_ECCPublicKey* pub)
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
    memcpy(pub->x, x, xlen);
    memcpy(pub->y, y, ylen);

    /* Unmarshal identifier */
    status = AJ_UnmarshalArgs(msg, "ay", &id->data, &id->size);

    return status;

Exit:
    return AJ_ERR_INVALID;
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
    AJ_CredField field;
    AJ_ECCPublicKey pub;

    switch (id) {
    case AJ_PROPERTY_SEC_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) SECURITY_APPLICATION_VERSION);
        break;

    case AJ_PROPERTY_SEC_APPLICATION_STATE:
        status = AJ_MarshalArgs(reply, "q", claimState);
        break;

    case AJ_PROPERTY_SEC_MANIFEST_DIGEST:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_SEC_ECC_PUBLICKEY:
        status = AJ_CredentialGetECCPublicKey(AJ_ECC_SIG, NULL, NULL, &pub);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_MarshalArgs(reply, "(yyayay)", pub.alg, pub.crv, pub.x, sizeof (pub.x), pub.y, sizeof (pub.y));
        break;

    case AJ_PROPERTY_SEC_MANUFACTURER_CERTIFICATE:
        status = AJ_CredentialGet(AJ_CERTIFICATE_OEM_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &field);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_SetMsgBody(reply, 'a', field.data, field.size);
        break;

    case AJ_PROPERTY_SEC_MANIFEST_TEMPLATE:
        //TODO: work in progress
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
            return status;
        }
        status = AJ_SetMsgBody(reply, 'a', field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_MANIFEST:
        status = AJ_CredentialGet(AJ_CRED_TYPE_MANIFEST, NULL, NULL, &field);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_SetMsgBody(reply, 'a', field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_IDENTITY_CERT_ID:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_POLICY_VERSION:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_POLICY:
        status = AJ_CredentialGet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, NULL, &field);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_SetMsgBody(reply, '(', field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_DEFAULT_POLICY:
        status = AJ_CredentialGet(AJ_POLICY_DEFAULT | AJ_CRED_TYPE_POLICY, NULL, NULL, &field);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_SetMsgBody(reply, '(', field.data, field.size);
        break;

    case AJ_PROPERTY_MANAGED_MEMBERSHIP_SUMMARY:
        //TODO: work in progress
        break;

    default:
        status = AJ_ERR_UNEXPECTED;
        break;
    }

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
    status = UnmarshalECCPublicKey(msg, &id, &pub);
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
    status = UnmarshalECCPublicKey(msg, &id, &pub);
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
    /* Store identity certificate */
    status = AJ_CredentialSet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get manifest */
    status = AJ_GetMsgBody(msg, 'a', &data.data, &data.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store manifest */
    status = AJ_CredentialSet(AJ_CRED_TYPE_MANIFEST, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }

    claimState = APP_STATE_CLAIMED;
    status = SetClaimState(APP_STATE_CLAIMED);

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

    AJ_ClearCredentials(0);

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
    /* Store identity certificate */
    status = AJ_CredentialSet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get manifest */
    status = AJ_GetMsgBody(msg, 'a', &data.data, &data.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store manifest */
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
    /* Store policy */
    status = AJ_CredentialSet(AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        return status;
    }

    status = AJ_MarshalReplyMsg(msg, reply);

    return status;
}

AJ_Status AJ_SecurityResetPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_SecurityResetPolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_CredentialDelete(AJ_CRED_TYPE_POLICY, NULL);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
    }

    status = AJ_MarshalReplyMsg(msg, reply);

    return status;
}

AJ_Status AJ_SecurityInstallMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityInstallMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityRemoveMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityRemoveMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}
