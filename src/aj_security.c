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

#include <ajtcl/aj_authorisation.h>
#include <ajtcl/aj_target.h>
#include <ajtcl/aj_security.h>
#include <ajtcl/aj_std.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_guid.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_crypto.h>

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

static uint8_t initialised = FALSE;
static uint8_t emit = FALSE;
static uint8_t clear = FALSE;
static uint16_t claimState = APP_STATE_NOT_CLAIMABLE;
static uint16_t claimCapabilities = 0;
static uint16_t claimInfo = 0;

static AJ_Status SetClaimState(uint16_t state)
{
    AJ_Status status;
    AJ_CredField data;

    /* If app not claimed and manifest template changes, do not update */
    if ((APP_STATE_CLAIMED != claimState) && (APP_STATE_NEED_UPDATE == state)) {
        return AJ_OK;
    }

    data.size = sizeof (uint16_t);
    data.data = (uint8_t*) &state;
    status = AJ_CredentialSet(AJ_CONFIG_CLAIMSTATE | AJ_CRED_TYPE_CONFIG, NULL, 0xFFFFFFFF, &data);

    if (AJ_OK == status) {
        /* Set in memory state */
        claimState = state;
        /* State changed, emit signal */
        emit = TRUE;
    }

    return status;
}

static AJ_Status GetClaimState(uint16_t* state)
{
    AJ_Status status;
    AJ_CredField data;

    data.size = sizeof (uint16_t);
    data.data = (uint8_t*) state;
    status = AJ_CredentialGet(AJ_CONFIG_CLAIMSTATE | AJ_CRED_TYPE_CONFIG, NULL, NULL, &data);

    return status;
}

void AJ_SecuritySetClaimConfig(AJ_BusAttachment* bus, uint16_t state, uint16_t capabilities, uint16_t info)
{
    claimCapabilities = capabilities;
    claimInfo = info;
    SetClaimState(state);
    AJ_ApplicationStateSignal(bus);
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

    AJ_InfoPrintf(("AJ_SecurityInit(bus=%p): Initialised = %x\n", bus, initialised));

    if (initialised) {
        return AJ_OK;
    }

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

    /* Get the initial claim state */
    status = GetClaimState(&claimState);
    if (AJ_OK != status) {
        /* If not stored, default to claimable */
        claimState = APP_STATE_CLAIMABLE;
        claimCapabilities = CLAIM_CAPABILITY_ECDHE_NULL | CLAIM_CAPABILITY_ECDHE_PSK;
    }

    /*
     * Bind to the security management port
     */
    AJ_InfoPrintf(("AJ_SecurityInit(bus=%p): Bind Session Port %d\n", bus, AJ_SECURE_MGMT_PORT));
    status = AJ_BusBindSessionPort(bus, AJ_SECURE_MGMT_PORT, NULL, 0);

    return status;
}

AJ_Status AJ_SecurityBound(AJ_BusAttachment* bus)
{
    AJ_InfoPrintf(("AJ_SecurityBound(bus=%p): Bind OK\n", bus));

    AJ_AuthorisationInit();
    emit = TRUE;
    initialised = TRUE;

    return AJ_OK;
}

void AJ_SecurityClose(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityClose(bus=%p)\n", bus));

    /* We don't need to wait for the response */
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_UNBIND_SESSION, AJ_BusDestination, 0, AJ_FLAG_NO_REPLY_EXPECTED, 0);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "q", AJ_SECURE_MGMT_PORT);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    initialised = FALSE;
    AJ_AuthorisationClose();
}

AJ_Status AJ_UnmarshalECCPublicKey(AJ_Message* msg, AJ_ECCPublicKey* pub, DER_Element* kid)
{
    AJ_Status status = AJ_OK;
    uint8_t* x;
    uint8_t* y;
    size_t xlen;
    size_t ylen;

    if (NULL == kid) {
        /* Unmarshal key */
        status = AJ_UnmarshalArgs(msg, "(yyayay)", &pub->alg, &pub->crv, &x, &xlen, &y, &ylen);
    } else {
        /* Unmarshal key with identifier */
        status = AJ_UnmarshalArgs(msg, "(yyayayay)", &pub->alg, &pub->crv, &kid->data, &kid->size, &x, &xlen, &y, &ylen);
    }
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

AJ_Status AJ_GetCertificateId(X509CertificateChain* chain, AJ_CertificateId* id)
{
    AJ_Status status;
    uint32_t type;

    AJ_ASSERT(id);
    AJ_ASSERT(chain);
    /* AKI and type is in the root certificate */
    id->aki.data = chain->certificate.tbs.extensions.aki.data;
    id->aki.size = chain->certificate.tbs.extensions.aki.size;
    type = chain->certificate.tbs.extensions.type;
    while (chain->next) {
        chain = chain->next;
    }
    /* Serial number is in the leaf certificate */
    id->serial.data = chain->certificate.tbs.serial.data;
    id->serial.size = chain->certificate.tbs.serial.size;
    /* Authority PublicKey is in the policy */
    status = AJ_PolicyGetCAPublicKey(type, &id->aki, &id->pub);

    return status;
}

static AJ_Status SetDefaultPolicy(AJ_PermissionPeer* ca, AJ_PermissionPeer* admin)
{
    AJ_Status status;
    AJ_CredField data = { 0, NULL };

    /* Create a marshalled policy message - 512 bytes should be sufficient */
    data.size = 512;
    data.data = AJ_Malloc(data.size);
    if (NULL == data.data) {
        goto Exit;
    }
    status = AJ_MarshalDefaultPolicy(&data, ca, admin);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store the default policy */
    status = AJ_CredentialSet(AJ_POLICY_DEFAULT | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &data);

Exit:
    AJ_CredFieldFree(&data);
    return status;
}

//SIG = a(ayayyyayay)
static AJ_Status MarshalMembershipIds(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    AJ_CredField data = { 0, NULL };
    X509CertificateChain* chain = NULL;
    AJ_CertificateId certificate;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        data.data = NULL;
        status = AJ_CredentialGetNext(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &data, &slot);
        slot++;
        if (AJ_OK == status) {
            status = AJ_X509ChainFromBuffer(&chain, &data);
            if (AJ_OK != status) {
                goto Exit;
            }
            status = AJ_GetCertificateId(chain, &certificate);
            if (AJ_OK != status) {
                goto Exit;
            }
            AJ_X509ChainFree(chain);
            chain = NULL;
            status = AJ_MarshalArgs(msg, "(ayay(yyayay))",
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

Exit:
    AJ_X509ChainFree(chain);
    AJ_CredFieldFree(&data);
    return status;
}

AJ_Status AJ_ApplicationStateSignal(AJ_BusAttachment* bus)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_ECCPublicKey pub;

    /* Clear session keys if required */
    if (clear) {
        AJ_InfoPrintf(("AJ_ApplicationStateSignal(bus=%p): Clear session keys\n", bus));
        AJ_GUID_ClearNameMap();
        clear = FALSE;
    }
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
    AJ_CredField field = { 0, NULL };
    AJ_ECCPublicKey pub;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    uint32_t version;
    AJ_Manifest* manifest = NULL;
    AJ_Policy* policy = NULL;
    AJ_CertificateId certificate;
    X509CertificateChain* chain = NULL;

    AJ_InfoPrintf(("SecurityGetProperty(reply=%p, id=%x, context=%p)\n", reply, id, context));

    switch (id) {
    case AJ_PROPERTY_APPLICATION_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) APPLICATION_VERSION);
        break;

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
        status = AJ_ManifestDigest(&field, digest);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalArgs(reply, "(yay)", DIGEST_ALG_SHA256, digest, AJ_SHA256_DIGEST_LENGTH);
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
        status = AJ_X509ChainFromBuffer(&chain, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_X509ChainMarshal(chain, reply);
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
        status = AJ_X509ChainFromBuffer(&chain, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_X509ChainMarshal(chain, reply);
        break;

    case AJ_PROPERTY_MANAGED_MANIFEST:
        status = AJ_CredentialGet(AJ_CRED_TYPE_MANIFEST, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_ManifestFromBuffer(&manifest, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_ManifestMarshal(manifest, reply);
        if (AJ_OK != status) {
            break;
        }
        break;

    case AJ_PROPERTY_MANAGED_IDENTITY_CERT_ID:
        status = AJ_CredentialGet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_X509ChainFromBuffer(&chain, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_GetCertificateId(chain, &certificate);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalArgs(reply, "(ayay(yyayay))",
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
        status = AJ_CredentialGet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_PolicyFromBuffer(&policy, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_PolicyMarshal(policy, reply);
        if (AJ_OK != status) {
            break;
        }
        AJ_PolicyFree(policy);
        policy = NULL;
        break;

    case AJ_PROPERTY_MANAGED_DEFAULT_POLICY:
        status = AJ_CredentialGet(AJ_POLICY_DEFAULT | AJ_CRED_TYPE_POLICY, NULL, NULL, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_PolicyFromBuffer(&policy, &field);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_PolicyMarshal(policy, reply);
        if (AJ_OK != status) {
            break;
        }
        AJ_PolicyFree(policy);
        policy = NULL;
        break;

    case AJ_PROPERTY_MANAGED_MEMBERSHIP_SUMMARY:
        status = MarshalMembershipIds(reply);
        break;

    default:
        status = AJ_ERR_UNEXPECTED;
        break;
    }

    AJ_CredFieldFree(&field);
    AJ_X509ChainFree(chain);
    AJ_ManifestFree(manifest);
    AJ_PolicyFree(policy);

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
    AJ_PermissionPeer ca;
    AJ_PermissionPeer admin;
    AJ_ECCPublicKey pub;
    AJ_CredField data;
    X509CertificateChain* identity = NULL;
    AJ_CredField identity_data = { 0, NULL };
    AJ_Manifest* manifest = NULL;
    AJ_CredField manifest_data = { 0, NULL };
    X509Certificate* certificate;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];

    AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p)\n", msg, reply));

    if (APP_STATE_CLAIMABLE != claimState) {
        AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p): Not in claimable state\n", msg, reply));
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
    }

    /* Unmarshal certificate authority */
    status = AJ_UnmarshalECCPublicKey(msg, &ca.pub, NULL);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Unmarshal certificate authority identifier */
    status = AJ_UnmarshalArgs(msg, "ay", &ca.kid.data, &ca.kid.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (0 == ca.kid.size) {
        AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p): Empty AKI\n", msg, reply));
        status = AJ_ERR_SECURITY;
        goto Exit;
    }

    /* Unmarshal admin group guid */
    status = AJ_UnmarshalArgs(msg, "ay", &admin.group.data, &admin.group.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Store the admin group guid */
    data.size = admin.group.size;
    data.data = admin.group.data;
    status = AJ_CredentialSet(AJ_CONFIG_ADMIN_GROUP | AJ_CRED_TYPE_CONFIG, NULL, 0xFFFFFFFF, &data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Unmarshal admin certificate authority */
    status = AJ_UnmarshalECCPublicKey(msg, &admin.pub, NULL);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Unmarshal admin certificate authority identifier */
    status = AJ_UnmarshalArgs(msg, "ay", &admin.kid.data, &admin.kid.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (0 == admin.kid.size) {
        AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p): Empty AKI\n", msg, reply));
        status = AJ_ERR_SECURITY;
        goto Exit;
    }

    /* Unmarshal identity certificate */
    identity_data.data = msg->bus->sock.rx.readPtr;
    status = AJ_X509ChainUnmarshal(&identity, msg);
    if (AJ_OK != status) {
        identity_data.data = NULL;
        goto Exit;
    }
    identity_data.size = msg->bus->sock.rx.readPtr - identity_data.data;
    /* Allow additional 8 bytes for maximum padding */
    identity_data.size += 8;
    identity_data.data = AJ_Malloc(identity_data.size);
    if (NULL == identity_data.data) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    status = AJ_X509ChainToBuffer(identity, &identity_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Check leaf certificate public key is mine */
    certificate = AJ_X509LeafCertificate(identity);
    if (NULL == certificate) {
        status = AJ_ERR_SECURITY;
        goto Exit;
    }
    status = AJ_CredentialGetECCPublicKey(AJ_ECC_SIG, NULL, NULL, &pub);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (0 != memcmp((uint8_t*) &pub, &certificate->tbs.publickey, sizeof (pub))) {
        AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p): Unknown certificate\n", msg, reply));
        status = AJ_ERR_SECURITY_UNKNOWN_CERTIFICATE;
        goto Exit;
    }

    /* Store identity certificate as raw marshalled body */
    status = AJ_CredentialSet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, 0xFFFFFFFF, &identity_data);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Unmarshal manifest */
    manifest_data.data = msg->bus->sock.rx.readPtr;
    status = AJ_ManifestUnmarshal(&manifest, msg);
    if (AJ_OK != status) {
        manifest_data.data = NULL;
        goto Exit;
    }
    manifest_data.size = msg->bus->sock.rx.readPtr - manifest_data.data;
    /* Allow additional 8 bytes for maximum padding */
    manifest_data.size += 8;
    manifest_data.data = AJ_Malloc(manifest_data.size);
    if (NULL == manifest_data.data) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    status = AJ_ManifestToBuffer(manifest, &manifest_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Check digest of manifest matches that in certificate */
    AJ_ManifestDigest(&manifest_data, digest);
    if (sizeof (digest) != certificate->tbs.extensions.digest.size) {
        AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p): Digest mismatch\n", msg, reply));
        status = AJ_ERR_SECURITY_DIGEST_MISMATCH;
        goto Exit;
    }
    if (0 != memcmp(digest, certificate->tbs.extensions.digest.data, sizeof (digest))) {
        AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p): Digest mismatch\n", msg, reply));
        status = AJ_ERR_SECURITY_DIGEST_MISMATCH;
        goto Exit;
    }
    /* Store manifest as raw marshalled body */
    status = AJ_CredentialSet(AJ_CRED_TYPE_MANIFEST, NULL, 0xFFFFFFFF, &manifest_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_X509ChainFree(identity);
    identity = NULL;
    AJ_ManifestFree(manifest);
    manifest = NULL;
    AJ_CredFieldFree(&identity_data);
    AJ_CredFieldFree(&manifest_data);

    /* Set default policy */
    ca.type = AJ_PEER_TYPE_FROM_CA;
    ca.next = NULL;
    admin.type = AJ_PEER_TYPE_WITH_MEMBERSHIP;
    admin.next = NULL;
    status = SetDefaultPolicy(&ca, &admin);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Clear master secrets */
    status = AJ_ClearCredentials(AJ_GENERIC_MASTER_SECRET | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_ClearCredentials(AJ_GENERIC_ECDSA_MANIFEST | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_ClearCredentials(AJ_GENERIC_ECDSA_KEYS | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Clear session keys, can't do it now because we need to reply */
    clear = TRUE;

    /* Set claim state and save to nvram */
    status = SetClaimState(APP_STATE_CLAIMED);

Exit:
    AJ_X509ChainFree(identity);
    AJ_CredFieldFree(&identity_data);
    AJ_ManifestFree(manifest);
    AJ_CredFieldFree(&manifest_data);
    if (AJ_OK == status) {
        return AJ_MarshalReplyMsg(msg, reply);
    } else {
        /* Remove stored values on error */
        AJ_ClearCredentials(AJ_CONFIG_ADMIN_GROUP | AJ_CRED_TYPE_CONFIG);
        AJ_ClearCredentials(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE);
        AJ_ClearCredentials(AJ_CRED_TYPE_MANIFEST);
        AJ_ClearCredentials(AJ_POLICY_DEFAULT | AJ_CRED_TYPE_POLICY);
        return AJ_MarshalStatusMsg(msg, reply, status);
    }
}

/*
 * org.alljoyn.Bus.Security.ManagedApplication implementation
 */
AJ_Status AJ_SecurityResetMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_ECCPublicKey pub;
    AJ_ECCPrivateKey prv;

    AJ_InfoPrintf(("AJ_SecurityResetMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Clear everything out except ECDSA signature pair */
    AJ_CredentialGetECCPublicKey(AJ_ECC_SIG, NULL, NULL, &pub);
    AJ_CredentialGetECCPrivateKey(AJ_ECC_SIG, NULL, NULL, &prv);
    AJ_ClearCredentials(0);
    AJ_CredentialSetECCPublicKey(AJ_ECC_SIG, NULL, 0xFFFFFFFF, &pub);
    AJ_CredentialSetECCPrivateKey(AJ_ECC_SIG, NULL, 0xFFFFFFFF, &prv);

    /* Set claim state and emit signal*/
    status = SetClaimState(APP_STATE_CLAIMABLE);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Clear session keys, can't do it now because we need to reply */
    clear = TRUE;

    return AJ_MarshalReplyMsg(msg, reply);
Exit:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityUpdateIdentityMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    X509CertificateChain* identity = NULL;
    AJ_CredField identity_data = { 0, NULL };
    AJ_Manifest* manifest = NULL;
    AJ_CredField manifest_data = { 0, NULL };

    AJ_InfoPrintf(("AJ_SecurityUpdateIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Unmarshal identity certificate */
    identity_data.data = msg->bus->sock.rx.readPtr;
    status = AJ_X509ChainUnmarshal(&identity, msg);
    if (AJ_OK != status) {
        identity_data.data = NULL;
        goto Exit;
    }
    identity_data.size = msg->bus->sock.rx.readPtr - identity_data.data;
    /* Allow additional 8 bytes for maximum padding */
    identity_data.size += 8;
    identity_data.data = AJ_Malloc(identity_data.size);
    if (NULL == identity_data.data) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    status = AJ_X509ChainToBuffer(identity, &identity_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_X509ChainFree(identity);
    identity = NULL;
    /* Store identity certificate as raw marshalled body */
    status = AJ_CredentialSet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, 0xFFFFFFFF, &identity_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_CredFieldFree(&identity_data);

    /* Unmarshal manifest */
    manifest_data.data = msg->bus->sock.rx.readPtr;
    status = AJ_ManifestUnmarshal(&manifest, msg);
    if (AJ_OK != status) {
        manifest_data.data = NULL;
        goto Exit;
    }
    manifest_data.size = msg->bus->sock.rx.readPtr - manifest_data.data;
    /* Allow additional 8 bytes for maximum padding */
    manifest_data.size += 8;
    manifest_data.data = AJ_Malloc(manifest_data.size);
    if (NULL == manifest_data.data) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    status = AJ_ManifestToBuffer(manifest, &manifest_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_ManifestFree(manifest);
    manifest = NULL;
    /* Store manifest as raw marshalled body */
    status = AJ_CredentialSet(AJ_CRED_TYPE_MANIFEST, NULL, 0xFFFFFFFF, &manifest_data);

Exit:
    AJ_X509ChainFree(identity);
    AJ_CredFieldFree(&identity_data);
    AJ_ManifestFree(manifest);
    AJ_CredFieldFree(&manifest_data);
    if (AJ_OK == status) {
        return AJ_MarshalReplyMsg(msg, reply);
    } else {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
    }
}

AJ_Status AJ_SecurityUpdatePolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Policy* policy = NULL;
    AJ_CredField policy_data = { 0, NULL };

    AJ_InfoPrintf(("AJ_SecurityUpdatePolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Unmarshal policy */
    policy_data.data = msg->bus->sock.rx.readPtr;
    status = AJ_PolicyUnmarshal(&policy, msg);
    if (AJ_OK != status) {
        policy_data.data = NULL;
        goto Exit;
    }
    policy_data.size = msg->bus->sock.rx.readPtr - policy_data.data;
    /* Allow additional 8 bytes for maximum padding */
    policy_data.size += 8;
    policy_data.data = AJ_Malloc(policy_data.size);
    if (NULL == policy_data.data) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    status = AJ_PolicyToBuffer(policy, &policy_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_PolicyFree(policy);
    policy = NULL;
    /* Store policy as raw marshalled body */
    status = AJ_CredentialSet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, 0xFFFFFFFF, &policy_data);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_CredFieldFree(&policy_data);

    /* Clear master secrets */
    status = AJ_ClearCredentials(AJ_GENERIC_MASTER_SECRET | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_ClearCredentials(AJ_GENERIC_ECDSA_MANIFEST | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_ClearCredentials(AJ_GENERIC_ECDSA_KEYS | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Clear session keys, can't do it now because we need to reply */
    clear = TRUE;

Exit:
    AJ_PolicyFree(policy);
    AJ_CredFieldFree(&policy_data);
    if (AJ_OK == status) {
        return AJ_MarshalReplyMsg(msg, reply);
    } else {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
}

AJ_Status AJ_SecurityResetPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_SecurityResetPolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Delete installed policy */
    status = AJ_CredentialDelete(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Clear master secrets */
    status = AJ_ClearCredentials(AJ_GENERIC_MASTER_SECRET | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_ClearCredentials(AJ_GENERIC_ECDSA_MANIFEST | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_ClearCredentials(AJ_GENERIC_ECDSA_KEYS | AJ_CRED_TYPE_GENERIC);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Clear session keys, can't do it now because we need to reply */
    clear = TRUE;

Exit:
    if (AJ_OK == status) {
        return AJ_MarshalReplyMsg(msg, reply);
    } else {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
}

AJ_Status AJ_SecurityInstallMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredField id = { 0, NULL };
    X509CertificateChain* membership = NULL;
    AJ_CredField membership_data = { 0, NULL };
    AJ_CertificateId certificate;
    uint8_t* tmp;

    AJ_InfoPrintf(("AJ_SecurityInstallMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    /* Unmarshal membership certificate */
    membership_data.data = msg->bus->sock.rx.readPtr;
    status = AJ_X509ChainUnmarshal(&membership, msg);
    if (AJ_OK != status) {
        membership_data.data = NULL;
        goto Exit;
    }
    membership_data.size = msg->bus->sock.rx.readPtr - membership_data.data;
    /* Allow additional 8 bytes for maximum padding */
    membership_data.size += 8;
    membership_data.data = AJ_Malloc(membership_data.size);
    if (NULL == membership_data.data) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    status = AJ_X509ChainToBuffer(membership, &membership_data);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_GetCertificateId(membership, &certificate);
    if (AJ_OK != status) {
        goto Exit;
    }
    id.size = certificate.serial.size + certificate.aki.size;
    id.data = AJ_Malloc(id.size);
    if (NULL == id.data) {
        goto Exit;
    }
    tmp = id.data;
    memcpy(tmp, certificate.serial.data, certificate.serial.size);
    tmp += certificate.serial.size;
    memcpy(tmp, certificate.aki.data, certificate.aki.size);
    tmp += certificate.aki.size;
    /* Store membership certificate as raw marshalled body */
    status = AJ_CredentialSet(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, &id, 0xFFFFFFFF, &membership_data);

Exit:
    AJ_CredFieldFree(&id);
    AJ_CredFieldFree(&membership_data);
    if (AJ_OK == status) {
        return AJ_MarshalReplyMsg(msg, reply);
    } else {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
}

AJ_Status AJ_SecurityRemoveMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredField id = { 0, NULL };
    AJ_CertificateId certificate;
    uint8_t* x;
    uint8_t* y;
    size_t xlen;
    size_t ylen;
    uint8_t* tmp;

    AJ_InfoPrintf(("AJ_SecurityRemoveMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_UnmarshalArgs(reply, "(ayay(yyayay))",
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
    id.size = certificate.serial.size + certificate.aki.size;
    id.data = AJ_Malloc(id.size);
    if (NULL == id.data) {
        goto Exit;
    }
    tmp = id.data;
    memcpy(tmp, certificate.serial.data, certificate.serial.size);
    tmp += certificate.serial.size;
    memcpy(tmp, certificate.aki.data, certificate.aki.size);
    tmp += certificate.aki.size;
    status = AJ_CredentialDelete(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, &id);

Exit:
    AJ_CredFieldFree(&id);
    if (AJ_OK == status) {
        return AJ_MarshalReplyMsg(msg, reply);
    } else {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
}
