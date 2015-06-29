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
#define AJ_MODULE AUTHENTICATION

#include "aj_target.h"
#include "aj_debug.h"
#include "aj_authentication.h"
#include "aj_cert.h"
#include "aj_peer.h"
#include "aj_creds.h"
#include "aj_auth_listener.h"
#include "aj_crypto.h"
#include "aj_msg_priv.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgAUTHENTICATION = 0;
#endif

// Enabled suites (this should initialize to zero)
static uint32_t suites[AJ_AUTH_SUITES_NUM];

#define SIG_FMT            0
#define AUTH_VERIFIER_LEN  SHA256_DIGEST_LENGTH

// Type to use for structs when hashing for compatibility with standard client
#define HASH_AJ_ARG_STRUCT 'r'

static AJ_Status ComputeMasterSecret(AJ_AuthenticationContext* ctx, uint8_t* pms, size_t len)
{
    const uint8_t* data[2];
    uint8_t lens[2];

    AJ_InfoPrintf(("ComputeMasterSecret(ctx=%p, pms=%p, len=%d)\n", ctx, pms, len));

    data[0] = pms;
    lens[0] = len;
    data[1] = (uint8_t*) "master secret";
    lens[1] = 13;

    return AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), ctx->mastersecret, AJ_MASTER_SECRET_LEN);
}

static AJ_Status ComputeVerifier(AJ_AuthenticationContext* ctx, const char* label, uint8_t* buffer, size_t bufferlen)
{
    const uint8_t* data[3];
    uint8_t lens[3];
    uint8_t digest[SHA256_DIGEST_LENGTH];

    AJ_ConversationHash_GetDigest(ctx, digest, 1);

    data[0] = ctx->mastersecret;
    lens[0] = AJ_MASTER_SECRET_LEN;
    data[1] = (uint8_t*) label;
    lens[1] = (uint8_t) strlen(label);
    data[2] = digest;
    lens[2] = sizeof (digest);

    return AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), buffer, bufferlen);
}

static AJ_Status ECDHEMarshalV1(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t buf[1 + KEY_ECC_OLD_SZ];

    AJ_InfoPrintf(("ECDHEMarshalV1(ctx=%p, msg=%p)\n", ctx, msg));

    // Encode the public key
    buf[0] = KEY_CRV_NISTP256;
    AJ_BigEndianEncodePublicKey(&ctx->kectx.pub, &buf[1]);
    // Marshal the encoded key
    status = AJ_MarshalArgs(msg, "v", "ay", buf, sizeof (buf));
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, buf, sizeof (buf));

    return status;
}

static AJ_Status ECDHEMarshalV2(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("ECDHEMarshalV2(ctx=%p, msg=%p)\n", ctx, msg));

    // Marshal the encoded key
    status = AJ_MarshalArgs(msg, "v", "(yay)", ctx->kectx.pub.crv, ctx->kectx.pub.x, KEY_ECC_PUB_SZ);
    AJ_ASSERT(sizeof(uint8_t) == sizeof(ctx->kectx.pub.crv)); // TODO: remove after validation
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &ctx->kectx.pub.crv, sizeof (ctx->kectx.pub.crv));
    AJ_ASSERT(KEY_ECC_PUB_SZ == sizeof(ctx->kectx.pub.x)); // TODO: remove after validation
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kectx.pub.x, sizeof(ctx->kectx.pub.x));

    return status;
}

static AJ_Status ECDHEMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("ECDHEMarshal(ctx=%p, msg=%p)\n", ctx, msg));

    // Generate key pair if client
    if (AUTH_CLIENT == ctx->role) {
        status = AJ_GenerateECCKeyPair(&ctx->kectx.pub, &ctx->kectx.prv);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("ECDHEMarshal(ctx=%p, msg=%p): Key generation failed\n", ctx, msg));
            return status;
        }
    }

    if ((ctx->version >> 16) < 3) {
        status = ECDHEMarshalV1(ctx, msg);
    } else {
        status = ECDHEMarshalV2(ctx, msg);
    }

    return status;
}

static AJ_Status ECDHEUnmarshalV1(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t* data;
    size_t size;
    AJ_ECCPublicKey pub;
    AJ_ECCPublicKey secret;

    AJ_InfoPrintf(("ECDHEUnmarshalV1(ctx=%p, msg=%p)\n", ctx, msg));

    // Unmarshal the encoded key
    status = AJ_UnmarshalArgs(msg, "v", "ay", &data, &size);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("ECDHEUnmarshalV1(ctx=%p, msg=%p): Unmarshal error\n", ctx, msg));
        return status;
    }
    if ((1 + KEY_ECC_OLD_SZ) != size) {
        AJ_InfoPrintf(("ECDHEUnmarshalV1(ctx=%p, msg=%p): Invalid key material\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    if (KEY_CRV_NISTP256 != data[0]) {
        AJ_InfoPrintf(("ECDHEUnmarshalV1(ctx=%p, msg=%p): Invalid curve\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    // Decode the public key
    AJ_BigEndianDecodePublicKey(&pub, &data[1]);

    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, data, size);

    // Generate shared secret
    status = AJ_GenerateShareSecretOld(&pub, &ctx->kectx.prv, &secret);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("ECDHEUnmarshalV1(ctx=%p, msg=%p): Generate secret error\n", ctx, msg));
        return status;
    }

    // Encode the shared secret
    size = KEY_ECC_OLD_SZ;
    data = AJ_Malloc(size);
    if (NULL == data) {
        return AJ_ERR_RESOURCES;
    }
    AJ_BigEndianEncodePublicKey(&secret, data);
    status = ComputeMasterSecret(ctx, data, size);
    AJ_Free(data);

    return status;
}

static AJ_Status ECDHEUnmarshalV2(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t* data;
    size_t size;
    AJ_ECCPublicKey pub;
    AJ_ECCSecret sec;
    AJ_SHA256_Context sha;

    AJ_InfoPrintf(("ECDHEUnmarshalV2(ctx=%p, msg=%p)\n", ctx, msg));

    // Unmarshal the encoded key
    status = AJ_UnmarshalArgs(msg, "v", "(yay)", &pub.crv, &data, &size);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("ECDHEUnmarshalV2(ctx=%p, msg=%p): Unmarshal error\n", ctx, msg));
        return status;
    }
    if (KEY_CRV_NISTP256 != pub.crv) {
        AJ_InfoPrintf(("ECDHEUnmarshalV2(ctx=%p, msg=%p): Invalid curve\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    if (KEY_ECC_PUB_SZ != size) {
        AJ_InfoPrintf(("ECDHEUnmarshalV2(ctx=%p, msg=%p): Invalid key material\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    // Copy the public key
    memcpy(pub.x, data, KEY_ECC_SZ);
    memcpy(pub.y, data + KEY_ECC_SZ, KEY_ECC_SZ);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &pub.crv, sizeof (pub.crv));
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, data, size);

    // Generate shared secret
    status = AJ_GenerateShareSecret(&pub, &ctx->kectx.prv, &sec);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("ECDHEUnmarshalV2(ctx=%p, msg=%p): Generate secret error\n", ctx, msg));
        return status;
    }

    // Encode the shared secret
    size = SHA256_DIGEST_LENGTH;
    data = AJ_Malloc(size);
    if (NULL == data) {
        return AJ_ERR_RESOURCES;
    }
    AJ_SHA256_Init(&sha);
    AJ_SHA256_Update(&sha, sec.x, KEY_ECC_SZ);
    AJ_SHA256_Final(&sha, data);
    status = ComputeMasterSecret(ctx, data, size);
    AJ_Free(data);

    return status;
}

static AJ_Status ECDHEUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("ECDHEUnmarshal(ctx=%p, msg=%p)\n", ctx, msg));

    // Generate key pair if server
    if (AUTH_SERVER == ctx->role) {
        status = AJ_GenerateECCKeyPair(&ctx->kectx.pub, &ctx->kectx.prv);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("ECDHEUnmarshal(ctx=%p, msg=%p): Key generation failed\n", ctx, msg));
            return status;
        }
    }

    if ((ctx->version >> 16) < 3) {
        status = ECDHEUnmarshalV1(ctx, msg);
    } else {
        status = ECDHEUnmarshalV2(ctx, msg);
    }

    return status;
}

AJ_Status AJ_KeyExchangeMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status = AJ_ERR_SECURITY;
    switch (0xFFFF0000 & ctx->suite) {
    case AUTH_KEYX_ECDHE:
        status = ECDHEMarshal(ctx, msg);
        break;
    }
    return status;
}

AJ_Status AJ_KeyExchangeUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status = AJ_ERR_SECURITY;
    switch (0xFFFF0000 & ctx->suite) {
    case AUTH_KEYX_ECDHE:
        status = ECDHEUnmarshal(ctx, msg);
        break;
    }
    return status;
}

static AJ_Status NULLMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Credential cred;
    uint8_t verifier[AUTH_VERIFIER_LEN];

    AJ_InfoPrintf(("NULLMarshal(ctx=%p, msg=%p)\n", ctx, msg));

    if (ctx->bus->authListenerCallback) {
        status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_NULL, 0, &cred);
        if (AJ_OK == status) {
            ctx->expiration = cred.expiration;
        }
    }
    if (AUTH_CLIENT == ctx->role) {
        status = ComputeVerifier(ctx, "client finished", verifier, sizeof (verifier));
    } else {
        status = ComputeVerifier(ctx, "server finished", verifier, sizeof (verifier));
    }
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    status = AJ_MarshalArgs(msg, "v", "ay", verifier, sizeof (verifier));

    if (AJ_OK == status) {
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, verifier, sizeof(verifier));

        AJ_ConversationHash_Update_HashHeader(ctx, CONVERSATION_V4, VERIFIER);
        AJ_ConversationHash_Update_MarshaledMessage(ctx, CONVERSATION_V4, msg);
    }

    return status;
}

static AJ_Status NULLUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t local[AUTH_VERIFIER_LEN];
    uint8_t* remote;
    size_t len;

    AJ_InfoPrintf(("NULLUnmarshal(ctx=%p, msg=%p)\n", ctx, msg));

    if (AUTH_CLIENT == ctx->role) {
        status = ComputeVerifier(ctx, "server finished", local, sizeof (local));
    } else {
        status = ComputeVerifier(ctx, "client finished", local, sizeof (local));
    }
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    status = AJ_UnmarshalArgs(msg, "v", "ay", &remote, &len);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("NULLUnmarshal(ctx=%p, msg=%p): Unmarshal error\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    if (AUTH_VERIFIER_LEN != len) {
        AJ_InfoPrintf(("NULLUnmarshal(ctx=%p, msg=%p): Invalid signature size\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    if (0 != Crypto_Compare(local, remote, AUTH_VERIFIER_LEN)) {
        AJ_InfoPrintf(("NULLUnmarshal(ctx=%p, msg=%p): Invalid verifier\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, local, sizeof (local));

    return status;
}

static AJ_Status PSKCallbackV1(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    uint8_t data[128];
    size_t size = sizeof (data);

    /*
     * Assume application does not copy in more than this size buffer
     * Expiration not set by application
     */
    size = ctx->bus->pwdCallback(data, size);
    if (sizeof (data) < size) {
        return AJ_ERR_RESOURCES;
    }
    ctx->expiration = 0xFFFFFFFF;
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kactx.psk.hint, ctx->kactx.psk.size);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, data, size);

    AJ_ConversationHash_Update_HashHeader(ctx, CONVERSATION_V4, PSK);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, ctx->kactx.psk.hint, ctx->kactx.psk.size);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, data, size);

    return AJ_OK;
}

static AJ_Status PSKCallbackV2(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Credential cred;

    switch (ctx->role) {
    case AUTH_CLIENT:
        cred.direction = AJ_CRED_REQUEST;
        status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PUB_KEY, &cred);
        if (AJ_OK == status) {
            ctx->kactx.psk.hint = cred.data;
            ctx->kactx.psk.size = cred.len;
        }
        break;

    case AUTH_SERVER:
        cred.direction = AJ_CRED_RESPONSE;
        cred.data = ctx->kactx.psk.hint;
        cred.len = ctx->kactx.psk.size;
        status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PUB_KEY, &cred);
        break;
    }
    cred.direction = AJ_CRED_REQUEST;
    status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PRV_KEY, &cred);
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    ctx->expiration = cred.expiration;
    // Hash in psk hint, then psk
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kactx.psk.hint, ctx->kactx.psk.size);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, cred.data, cred.len);

    AJ_ConversationHash_Update_HashHeader(ctx, CONVERSATION_V4, PSK);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, ctx->kactx.psk.hint, ctx->kactx.psk.size);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, cred.data, cred.len);

    return status;
}

static AJ_Status PSKCallback(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("PSKCallback(ctx=%p, msg=%p)\n", ctx, msg));

    if (ctx->bus->authListenerCallback) {
        status = PSKCallbackV2(ctx, msg);
    } else if (ctx->bus->pwdCallback) {
        status = PSKCallbackV1(ctx, msg);
    } else {
        status = AJ_ERR_SECURITY;
    }

    return status;
}

static AJ_Status PSKMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status = AJ_ERR_SECURITY;
    const char* anon = "<anonymous>";
    uint8_t verifier[AUTH_VERIFIER_LEN];

    AJ_InfoPrintf(("PSKMarshal(ctx=%p, msg=%p)\n", ctx, msg));

    switch (ctx->role) {
    case AUTH_CLIENT:
        // Default to anonymous
        ctx->kactx.psk.hint = (uint8_t*) anon;
        ctx->kactx.psk.size = strlen(anon);
        status = PSKCallback(ctx, msg);
        if (AJ_OK != status) {
            return AJ_ERR_SECURITY;
        }
        status = ComputeVerifier(ctx, "client finished", verifier, sizeof (verifier));
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, verifier, sizeof (verifier));

        break;

    case AUTH_SERVER:
        status = ComputeVerifier(ctx, "server finished", verifier, sizeof (verifier));
        break;
    }
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }

    status = AJ_MarshalArgs(msg, "v", "(ayay)", ctx->kactx.psk.hint, ctx->kactx.psk.size, verifier, sizeof (verifier));

    if ((AUTH_CLIENT == ctx->role) && (AJ_OK == status)) {
        AJ_ConversationHash_Update_HashHeader(ctx, CONVERSATION_V4, VERIFIER);
        AJ_ConversationHash_Update_MarshaledMessage(ctx, CONVERSATION_V4, msg);
    }

    return status;
}

static AJ_Status PSKUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t verifier[AUTH_VERIFIER_LEN];
    uint8_t* data;
    size_t size;

    AJ_InfoPrintf(("PSKUnmarshal(ctx=%p, msg=%p)\n", ctx, msg));

    status = AJ_UnmarshalArgs(msg, "v", "(ayay)", &ctx->kactx.psk.hint, &ctx->kactx.psk.size, &data, &size);
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    if (AUTH_VERIFIER_LEN != size) {
        return AJ_ERR_SECURITY;
    }

    switch (ctx->role) {
    case AUTH_CLIENT:
        status = ComputeVerifier(ctx, "server finished", verifier, sizeof (verifier));
        break;

    case AUTH_SERVER:
        status = PSKCallback(ctx, msg);
        if (AJ_OK != status) {
            return AJ_ERR_SECURITY;
        }
        status = ComputeVerifier(ctx, "client finished", verifier, sizeof (verifier));

        if (AJ_OK == status) {
            AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, verifier, sizeof(verifier));
        }
        break;

    default:
        return AJ_ERR_SECURITY;
    }
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }

    if (0 != Crypto_Compare(verifier, data, AUTH_VERIFIER_LEN)) {
        AJ_InfoPrintf(("PSKUnmarshal(ctx=%p, msg=%p): Invalid verifier\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }

    return status;
}

/*
 * Store certificate chain is a(yay)
 * KeyAuthentication call expects yv = ya(ay)
 * Need to convert from a(yay) to a(ay)
 */
static AJ_Status MarshalCertificates(AJ_AuthenticationContext* ctx, AJ_Message* msg, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message tmp;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t fmt;
    uint8_t* data;
    size_t size;

    AJ_LocalMsg(&bus, &hdr, &tmp, "a(yay)", field->data, field->size);

    status = AJ_UnmarshalContainer(&tmp, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalArgs(&tmp, "(yay)", &fmt, &data, &size);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalArgs(msg, "(ay)", data, size);
        if (AJ_OK != status) {
            goto Exit;
        }
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, data, size);
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(&tmp, &container1);

Exit:
    return status;
}

static AJ_Status ECDSAMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    AJ_ECCPrivateKey prv;
    AJ_ECCSignature sig;
    uint8_t verifier[SHA256_DIGEST_LENGTH];
    uint8_t fmt;
    AJ_CredField field;

    AJ_InfoPrintf(("AJ_ECDSA_Marshal(ctx=%p, msg=%p)\n", ctx, msg));

    field.data = NULL;
    field.size = 0;

    if (AUTH_CLIENT == ctx->role) {
        status = ComputeVerifier(ctx, "client finished", verifier, sizeof (verifier));
    } else {
        status = ComputeVerifier(ctx, "server finished", verifier, sizeof (verifier));
    }
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get private key from keystore */
    status = AJ_CredentialGetECCPrivateKey(AJ_ECC_SIG, NULL, NULL, &prv);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("GetPrivateKey(ctx=%p, prv=%p): Private key missing from keystore\n", ctx, prv));
        goto Exit;
    }

    /* Sign verifier */
    status = AJ_ECDSASignDigest(verifier, &prv, &sig);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_ECDSA_Marshal(msg=%p): Sign verifier error\n", msg));
        goto Exit;
    }
    AJ_ASSERT((KEY_ECC_SZ == sizeof(sig.r)) && (KEY_ECC_SZ == sizeof(sig.s))); // TODO: remove after validation
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, sig.r, sizeof(sig.r));
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, sig.s, sizeof(sig.s));
    /* Marshal signature */
    status = AJ_MarshalVariant(msg, "(vyv)");
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalArgs(msg, "v", "(yv)", SIG_FMT, "(ayay)", sig.r, KEY_ECC_SZ, sig.s, KEY_ECC_SZ);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get certificate chain from keystore */
    status = AJ_CredentialGet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &field);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Marshal certificate chain */
    fmt = CERT_FMT_X509_DER;
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &fmt, sizeof(fmt));
    status = AJ_MarshalArgs(msg, "y", fmt);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalVariant(msg, "a(ay)");
    if (AJ_OK != status) {
        goto Exit;
    }
    status = MarshalCertificates(ctx, msg, &field);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_ECDSA_Marshal(msg=%p): Marshal certificate chain error\n", msg));
        goto Exit;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    if ((AUTH_CLIENT == ctx->role) && (AJ_OK == status)) {
        AJ_ConversationHash_Update_HashHeader(ctx, CONVERSATION_V4, ECDSA);
        AJ_ConversationHash_Update_MarshaledMessage(ctx, CONVERSATION_V4, msg);
    }

Exit:
    AJ_CredFieldFree(&field);
    return status;
}

static AJ_Status ECDSAUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    const char* variant;
    uint8_t fmt;
    DER_Element der;
    AJ_CredField id;
    AJ_ECCPublicKey pub;
    AJ_ECCSignature sig;
    uint8_t* sig_r;
    uint8_t* sig_s;
    size_t len_r;
    size_t len_s;
    X509CertificateChain* head = NULL;
    X509CertificateChain* node = NULL;
    uint8_t trusted = 0;

    AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p)\n", msg));

    if (NULL == ctx->bus->authListenerCallback) {
        return AJ_ERR_SECURITY;
    }

    if (AUTH_CLIENT == ctx->role) {
        status = ComputeVerifier(ctx, "server finished", digest, sizeof (digest));
    } else {
        status = ComputeVerifier(ctx, "client finished", digest, sizeof (digest));
    }
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_UnmarshalVariant(msg, &variant);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (0 != strncmp(variant, "(vyv)", 5)) {
        goto Exit;
    }
    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Unmarshal signature */
    status = AJ_UnmarshalArgs(msg, "v", "(yv)", &fmt, "(ayay)", &sig_r, &len_r, &sig_s, &len_s);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (SIG_FMT != fmt) {
        goto Exit;
    }
    if ((KEY_ECC_SZ != len_r) || (KEY_ECC_SZ != len_s)) {
        goto Exit;
    }
    memcpy(sig.r, sig_r, KEY_ECC_SZ);
    memcpy(sig.s, sig_s, KEY_ECC_SZ);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, sig_r, KEY_ECC_SZ);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, sig_s, KEY_ECC_SZ);

    /* Unmarshal certificate chain */
    status = AJ_UnmarshalArgs(msg, "y", &fmt);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (CERT_FMT_X509_DER != fmt) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): DER encoding expected\n", msg));
        goto Exit;
    }
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &fmt, sizeof(fmt));
    status = AJ_UnmarshalVariant(msg, &variant);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (0 != strncmp(variant, "a(ay)", 5)) {
        goto Exit;
    }
    status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalArgs(msg, "(ay)", &der.data, &der.size);
        if (AJ_OK != status) {
            break;
        }
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, der.data, der.size);

        node = (X509CertificateChain*) AJ_Malloc(sizeof (X509CertificateChain));
        if (NULL == node) {
            AJ_WarnPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Resource error\n", msg));
            goto Exit;
        }
        /*
         * Push the certificate on to the front of the chain.
         * We do this before decoding so that it is cleaned up in case of error.
         */
        node->next = head;
        head = node;
        /* Set the der before its consumed */
        node->certificate.der.size = der.size;
        node->certificate.der.data = der.data;
        status = AJ_X509DecodeCertificateDER(&node->certificate, &der);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate decode failed\n", msg));
            goto Exit;
        }

        /*
         * If this is the first certificate, check that it signed the verifier
         * Also save the subject public key and manifest digest for authorisation check
         */
        if (NULL == node->next) {
            status = AJ_ECDSAVerifyDigest(digest, &sig, &node->certificate.tbs.publickey);
            if (AJ_OK != status) {
                AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Signature invalid\n", msg));
                goto Exit;
            }
            memcpy((uint8_t*) &ctx->kactx.ecdsa.subject, &node->certificate.tbs.publickey, sizeof (AJ_ECCPublicKey));
            if (SHA256_DIGEST_LENGTH != node->certificate.tbs.extensions.digest.size) {
                AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Manifest digest invalid\n", msg));
                goto Exit;
            }
            memcpy((uint8_t*) &ctx->kactx.ecdsa.manifest, node->certificate.tbs.extensions.digest.data, SHA256_DIGEST_LENGTH);
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate chain error %s\n", msg, AJ_StatusText(status)));
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (NULL == head) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate chain missing %s\n", msg, AJ_StatusText(status)));
        goto Exit;
    }

    /* Lookup certificate authority public key */
    id.size = head->certificate.tbs.extensions.aki.size;
    id.data = head->certificate.tbs.extensions.aki.data;
    status = AJ_CredentialGetECCPublicKey(AJ_ECC_CA, &id, NULL, &pub);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate authority unknown\n", msg));
        goto Exit;
    }
    /* Save the root issuer for authorisation check */
    memcpy((uint8_t*) &ctx->kactx.ecdsa.issuer, &pub, sizeof (AJ_ECCPublicKey));
    /* Verify the chain */
    status = AJ_X509VerifyChain(head, &pub);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate chain invalid\n", msg));
        goto Exit;
    }
    trusted = 1;

Exit:
    /* Free the cert chain */
    while (head) {
        node = head;
        head = head->next;
        AJ_Free(node);
    }
    return trusted ? AJ_OK : AJ_ERR_SECURITY;
}

AJ_Status AJ_KeyAuthenticationMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status = AJ_ERR_SECURITY;
    switch (ctx->suite) {
    case AUTH_SUITE_ECDHE_NULL:
        status = NULLMarshal(ctx, msg);
        break;

    case AUTH_SUITE_ECDHE_PSK:
        status = PSKMarshal(ctx, msg);
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        status = ECDSAMarshal(ctx, msg);
        break;
    }
    return status;
}

AJ_Status AJ_KeyAuthenticationUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status = AJ_ERR_SECURITY;
    switch (ctx->suite) {
    case AUTH_SUITE_ECDHE_NULL:
        status = NULLUnmarshal(ctx, msg);
        break;

    case AUTH_SUITE_ECDHE_PSK:
        status = PSKUnmarshal(ctx, msg);
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        status = ECDSAUnmarshal(ctx, msg);
        break;
    }
    return status;
}

uint8_t AJ_IsSuiteEnabled(uint32_t suite, uint32_t version)
{
    switch (suite) {
    case AUTH_SUITE_ECDHE_NULL:
        return 1 == suites[0];

    case AUTH_SUITE_ECDHE_PSK:
        return 1 == suites[1];

    case AUTH_SUITE_ECDHE_ECDSA:
        if (version < 3) {
            return 0;
        }
        return 1 == suites[2];

    default:
        return 0;
    }

    return 0;
}

void AJ_EnableSuite(uint32_t suite)
{
    switch (suite) {
    case AUTH_SUITE_ECDHE_NULL:
        suites[0] = 1;
        break;

    case AUTH_SUITE_ECDHE_PSK:
        suites[1] = 1;
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        suites[2] = 1;
        break;
    }
}

void AJ_ConversationHash_Initialize(AJ_AuthenticationContext* ctx)
{
    AJ_SHA256_Init(&ctx->hash);
}

static inline int ConversationVersionDoesNotApply(uint32_t conversationVersion, uint32_t currentAuthVersion)
{
    AJ_ASSERT((CONVERSATION_V1 == conversationVersion) || (CONVERSATION_V4 == conversationVersion));

    /* The conversation version itself is computed by taking (currentAuthVersion >> 16). We return true
     * if the current conversation version does NOT apply to the conversation version for the message being hashed.
     */
    if (CONVERSATION_V4 == conversationVersion) {
        return ((currentAuthVersion >> 16) != CONVERSATION_V4);
    } else {
        return ((currentAuthVersion >> 16) >= CONVERSATION_V4);
    }
}

void AJ_ConversationHash_Update_HashHeader(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, HashHeader hashHeader)
{
    /* Unlike C++, C doesn't allow specifying the underlying type of an enum,
     * so we make sure it will fit into a uint8_t.
     */
    uint8_t headerAsByte = (uint8_t)hashHeader;

    AJ_ASSERT(headerAsByte == hashHeader);
    AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, headerAsByte);
}

void AJ_ConversationHash_Update_UInt8(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, uint8_t byte)
{
    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }
    AJ_SHA256_Update(&ctx->hash, &byte, sizeof(byte));
}

void AJ_ConversationHash_Update_UInt8Array(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const uint8_t* buf, size_t bufSize)
{
    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }
    if (conversationVersion >= CONVERSATION_V4) {
        uint8_t v_uintLE[sizeof(uint32_t)];
        uint32_t bufSizeU32 = bufSize;
        HostU32ToLittleEndianU8(&bufSizeU32, sizeof(bufSizeU32), v_uintLE);
        AJ_SHA256_Update(&ctx->hash, v_uintLE, sizeof(v_uintLE));
    }
    AJ_SHA256_Update(&ctx->hash, buf, bufSize);
}

void AJ_ConversationHash_Update_String(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const char* str, size_t strSize)
{
    AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, (const uint8_t*)str, strSize);
}

void AJ_ConversationHash_Update_Arg(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg, AJ_Arg* arg)
{
    /* This needs to be the size of the largest integer type needing conversion. */
    uint8_t v_uintLE[sizeof(uint64_t)];

    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }

    /*
     * For array types, we follow the practice of the standard client here.
     * The base type character is left shifted 8 bits and ORd with 'a'.
     *
     * Integers and typeIds are converted into big-endian byte order before hashing.
     */

    /* We can get scalar arrays in two ways: with AJ_ARRAY_FLAG set and typeId of the underlying
     * type, or with the typeId as AJ_ARG_ARRAY and the arg's sigPtr containing a scalar type.
     * Check for the latter case, and if so, convert it to the former case and treat both the same.
     */
    if ((AJ_ARG_ARRAY == arg->typeId) && IsScalarType(*arg->sigPtr)) {
        AJ_ASSERT(1 == strlen(arg->sigPtr));
        arg->flags |= AJ_ARRAY_FLAG;
        arg->typeId = *arg->sigPtr;
    }

    if ((arg->flags & AJ_ARRAY_FLAG) != 0) {
        /* AJ_ARRAY_FLAG is for arrays of a single scalar type. Arrays of arbitrary types
         * are handled below.
         */
        uint16_t i = 0;

        /* numElements will be computed based on arg->len, which is a uint16_t. For compatibility
         * with standard client, though, we treat and hash as a uint32_t.
         */
        uint32_t numElements = 0;
        AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, AJ_ARG_ARRAY);
        AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, arg->typeId);

        switch (arg->typeId) {
        case AJ_ARG_BYTE:
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, arg->val.v_byte, arg->len);
            break;

        case AJ_ARG_UINT32:
            numElements = arg->len / sizeof(uint32_t);
#if HOST_IS_LITTLE_ENDIAN
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, (const uint8_t*)&numElements, sizeof(numElements));
            /* Use conversation version 0 to suppress per-element length headers */
            AJ_ConversationHash_Update_UInt8Array(ctx, 0, (const uint8_t*)arg->val.v_uint32, arg->len);
#else
            HostU32ToLittleEndianU8(&numElements, sizeof(numElements), v_uintLE);
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, v_uintLE, sizeof(numElements));
            for (i = 0; i < numElements; i++) {
                HostU32ToLittleEndianU8(&arg->val.v_uint32[i], sizeof(arg->val.v_uint32[i]), v_uintLE);
                AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, v_uintLE, sizeof(arg->val.v_uint32[i]));
            }
#endif
            break;

        default:
            /* Unexpected. */
            AJ_AlwaysPrintf(("AJ_ConversationHash_Update_Arg got unknown array subtype: %c\n", arg->typeId));
            AJ_ASSERT(0);
            return;
        }
    } else {
        AJ_Status status;
        const char* signature;
        AJ_Arg innerArg;
        uint32_t numElements;

        /* Hash data type. */
        switch (arg->typeId) {
        case AJ_ARG_STRUCT:
            AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, 0); // Not an array.
            /* Compatibility with standard client: it uses typeId 'r' for structs, whereas thin client
             * and wire protocol use '('.
             */
            AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, HASH_AJ_ARG_STRUCT);
            break;

        case AJ_ARG_ARRAY:
            AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, AJ_ARG_ARRAY);
            /* Non-scalar arrays have zero as the base type. */
            AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, 0);
            break;

        default:
            AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, 0); // Not an array.
            AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, arg->typeId);
            break;
        }

        /* Hash contents. */
        switch (arg->typeId) {
        case AJ_ARG_BYTE:
            AJ_ConversationHash_Update_UInt8(ctx, conversationVersion, *arg->val.v_byte);
            break;

        case AJ_ARG_UINT16:
            HostU16ToLittleEndianU8(arg->val.v_uint16, sizeof(*arg->val.v_uint16), v_uintLE);
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, v_uintLE, sizeof(*arg->val.v_uint16));
            break;

        case AJ_ARG_UINT32:
            HostU32ToLittleEndianU8(arg->val.v_uint32, sizeof(*arg->val.v_uint32), v_uintLE);
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, v_uintLE, sizeof(*arg->val.v_uint32));
            break;

        case AJ_ARG_UINT64:
            HostU64ToLittleEndianU8(arg->val.v_uint64, sizeof(*arg->val.v_uint64), v_uintLE);
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, v_uintLE, sizeof(*arg->val.v_uint64));
            break;

        case AJ_ARG_STRING:
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, (const uint8_t*)arg->val.v_string, arg->len);
            break;

        case AJ_ARG_VARIANT:
            if (TYPE_FLAG(*arg->val.v_string) & AJ_CONTAINER) {
                status = AJ_UnmarshalContainer(msg, &innerArg, *arg->val.v_string);
                if (AJ_OK != status) {
                    break;
                }
                AJ_ConversationHash_Update_Arg(ctx, conversationVersion, msg, &innerArg);
                status = AJ_UnmarshalCloseContainer(msg, &innerArg);
            } else {
                status = AJ_UnmarshalArg(msg, &innerArg);
                if (AJ_OK != status) {
                    break;
                }
                AJ_ConversationHash_Update_Arg(ctx, conversationVersion, msg, &innerArg);
            }
            break;

        case AJ_ARG_ARRAY:
            do {
                if (TYPE_FLAG(*arg->sigPtr) & AJ_CONTAINER) {
                    status = AJ_UnmarshalContainer(msg, &innerArg, *arg->sigPtr);
                    if (AJ_OK != status) {
                        break;
                    }
                    AJ_ConversationHash_Update_Arg(ctx, conversationVersion, msg, &innerArg);
                    status = AJ_UnmarshalCloseContainer(msg, &innerArg);
                } else {
                    status = AJ_UnmarshalArg(msg, &innerArg);
                    if (AJ_OK != status) {
                        break;
                    }
                    AJ_ConversationHash_Update_Arg(ctx, conversationVersion, msg, &innerArg);
                }
            } while (AJ_OK == status);
            /* We should only have broken out of the above loop when we're out of array elements. */
            AJ_ASSERT(AJ_ERR_NO_MORE == status);
            break;

        case AJ_ARG_STRUCT:
            for (signature = arg->sigPtr, numElements = 0; *signature != AJ_STRUCT_CLOSE; signature++, numElements++) {
                /* We don't currently support any aggregate types other than arrays inside structs. */
                AJ_ASSERT(!(TYPE_FLAG(*signature) & AJ_CONTAINER) || (AJ_ARG_ARRAY == *signature));
                if (AJ_ARG_ARRAY == *signature) {
                    /* Only count an array as one element; the character following the 'a' is the underlying type. */
                    signature++;
                }
            }
            HostU32ToLittleEndianU8(&numElements, sizeof(numElements), v_uintLE);
            AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, v_uintLE, sizeof(numElements));
            for (status = AJ_OK, signature = AJ_NextArgSig(msg);
                 (AJ_OK == status) && (*signature != AJ_STRUCT_CLOSE);
                 signature = AJ_NextArgSig(msg)) {
                status = AJ_UnmarshalArg(msg, &innerArg);
                if (AJ_OK == status) {
                    AJ_ConversationHash_Update_Arg(ctx, conversationVersion, msg, &innerArg);
                }
            }
            break;

        default:
            /* Unsupported, unexpected type. */
            AJ_AlwaysPrintf(("AJ_ConversationHash_Update_Arg got unknown type: %c\n", arg->typeId));
            AJ_ASSERT(0);
            return;
        }
    }
}

void AJ_ConversationHash_Update_UnmarshaledMessage(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    AJ_Arg arg;

    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }

    status = AJ_ResetArgs(msg);
    AJ_ASSERT(AJ_OK == status);
    while ((msg->bodyBytes > 0) && (AJ_OK == status)) {
        const char* sig = AJ_NextArgSig(msg);
        if (TYPE_FLAG(*sig) & AJ_CONTAINER) {
            status = AJ_UnmarshalContainer(msg, &arg, *sig);
            if (AJ_OK != status) {
                break;
            }
            AJ_ConversationHash_Update_Arg(ctx, conversationVersion, msg, &arg);
            status = AJ_UnmarshalCloseContainer(msg, &arg);
        } else {
            status = AJ_UnmarshalArg(msg, &arg);
            if (AJ_OK == status) {
                AJ_ConversationHash_Update_Arg(ctx, conversationVersion, msg, &arg);
            }
        }
    }

    /* Return the message reset to caller as promised. */
    status = AJ_ResetArgs(msg);
    AJ_ASSERT(AJ_OK == status);
}

void AJ_ConversationHash_Update_MarshaledMessage(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg)
{
    /* This function is used to hash a message we're about to send. In this case, the state of the AJ_Message
     * is not suitable for unmarshaling. We create a copy that is suitable based on the buffer about to be transmitted.
     */
    AJ_Message duplicateMessage;
    AJ_MsgHeader duplicateHeader;
    AJ_BusAttachment duplicateBus;
    uint8_t* duplicateBuffer = NULL;

    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }

    /* Duplicate the state. */
    memcpy(&duplicateMessage, msg, sizeof(duplicateMessage));
    memcpy(&duplicateHeader, msg->hdr, sizeof(duplicateHeader));
    memcpy(&duplicateBus, msg->bus, sizeof(duplicateBus));

    duplicateMessage.hdr = &duplicateHeader;
    duplicateMessage.bus = &duplicateBus;

    /* If the message's endianness is different from the host's, we have to copy the message
     * buffer as unmarshaling will turn it back into host byte order. Otherwise we can
     * reuse the buffer.
     */
    if (msg->hdr->endianess == HOST_ENDIANESS) {
        AJ_IOBufInit(&duplicateMessage.bus->sock.rx, msg->bus->sock.tx.bufStart, msg->bus->sock.tx.bufSize, AJ_IO_BUF_RX, msg->bus->sock.tx.context);
    } else {
        duplicateBuffer = (uint8_t*)AJ_Malloc(msg->bus->sock.tx.bufSize);
        AJ_ASSERT(NULL != duplicateBuffer);
        if (NULL == duplicateBuffer) {
            /* Nothing we can really do here! */
            AJ_AlwaysPrintf(("AJ_ConversationHash_Update_MarshaledMessage: Out of memory allocating duplicate buffer\n"));
            return;
        }
        memcpy(duplicateBuffer, msg->bus->sock.tx.bufStart, msg->bus->sock.tx.bufSize);
        AJ_IOBufInit(&duplicateMessage.bus->sock.rx, duplicateBuffer, msg->bus->sock.tx.bufSize, AJ_IO_BUF_RX, msg->bus->sock.tx.context);
    }

    /* Skip past the header and pad to the actual content. The header is null-padded to an 8-byte boundary.
     * See AJ_UnmarshalMsg in aj_msg.c.
     */
    duplicateMessage.bus->sock.rx.readPtr += sizeof(AJ_MsgHeader) + msg->hdr->headerLen + HEADERPAD(msg->hdr->headerLen);

    /* Fix up the necessary fields so the unmarshaling functions will work. */
    duplicateMessage.hdr->bodyLen = msg->bodyBytes;
    duplicateMessage.sigOffset = 0;

    /* Now hash. */
    AJ_ConversationHash_Update_UnmarshaledMessage(ctx, conversationVersion, &duplicateMessage);

    if (NULL != duplicateBuffer) {
        AJ_Free(duplicateBuffer);
    }
}

void AJ_ConversationHash_GetDigest(AJ_AuthenticationContext* ctx, uint8_t* digest, const uint8_t keepAlive)
{
    AJ_SHA256_GetDigest(&ctx->hash, digest, keepAlive);
}