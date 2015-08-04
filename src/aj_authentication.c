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

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_authorisation.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_auth_listener.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_msg_priv.h>
#include <ajtcl/aj_security.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgAUTHENTICATION = 0;
#endif

#define SIG_FMT            0
#define AUTH_VERIFIER_LEN  AJ_SHA256_DIGEST_LENGTH

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
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    AJ_Status status;

    status = AJ_ConversationHash_GetDigest(ctx, digest);
    if (AJ_OK != status) {
        return status;
    }

    data[0] = ctx->mastersecret;
    lens[0] = AJ_MASTER_SECRET_LEN;
    data[1] = (uint8_t*) label;
    lens[1] = (uint8_t) strlen(label);
    data[2] = digest;
    lens[2] = sizeof (digest);

    return AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), buffer, bufferlen);
}

static AJ_Status ComputePSKVerifier(AJ_AuthenticationContext* ctx, const char* label, uint8_t* buffer, size_t bufferlen)
{
    const uint8_t* data[5];
    uint8_t lens[5];
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    AJ_Status status;

    status = AJ_ConversationHash_GetDigest(ctx, digest);
    if (status != AJ_OK) {
        return status;
    }

    data[0] = ctx->mastersecret;
    lens[0] = AJ_MASTER_SECRET_LEN;
    data[1] = (uint8_t*)label;
    lens[1] = (uint8_t)strlen(label);
    data[2] = digest;
    lens[2] = sizeof(digest);
    data[3] = ctx->kactx.psk.hint;
    AJ_ASSERT(ctx->kactx.psk.hintSize <= 0xFF);
    lens[3] = (uint8_t)ctx->kactx.psk.hintSize;
    data[4] = ctx->kactx.psk.key;
    AJ_ASSERT(ctx->kactx.psk.keySize <= 0xFF);
    lens[4] = (uint8_t)ctx->kactx.psk.keySize;

    AJ_ASSERT(bufferlen <= 0xFFFFFFFF);
    return AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), buffer, (uint32_t)bufferlen);
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

static AJ_Status ECDHEMarshalV3(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("ECDHEMarshalV3(ctx=%p, msg=%p)\n", ctx, msg));

    // Marshal the encoded key
    status = AJ_MarshalArgs(msg, "v", "(yay)", ctx->kectx.pub.crv, ctx->kectx.pub.x, KEY_ECC_PUB_SZ);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &ctx->kectx.pub.crv, sizeof (ctx->kectx.pub.crv));
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kectx.pub.x, KEY_ECC_PUB_SZ);

    return status;
}

static AJ_Status ECDHEMarshalV4(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("ECDHEMarshalV4(ctx=%p, msg=%p)\n", ctx, msg));

    // Marshal the encoded key
    status = AJ_MarshalArgs(msg, "v", "(yyayay)", ctx->kectx.pub.alg, ctx->kectx.pub.crv, ctx->kectx.pub.x, KEY_ECC_SZ, ctx->kectx.pub.y, KEY_ECC_SZ);

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

    switch (ctx->version >> 16) {
    case 1:
    case 2:
        status = ECDHEMarshalV1(ctx, msg);
        break;

    case 3:
        status = ECDHEMarshalV3(ctx, msg);
        break;

    case 4:
        status = ECDHEMarshalV4(ctx, msg);
        break;

    default:
        status = AJ_ERR_INVALID;
        break;
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
    data = (uint8_t*) AJ_Malloc(size);
    if (NULL == data) {
        return AJ_ERR_RESOURCES;
    }
    AJ_BigEndianEncodePublicKey(&secret, data);
    status = ComputeMasterSecret(ctx, data, size);
    AJ_Free(data);

    return status;
}

static AJ_Status GenerateShareSecret(AJ_AuthenticationContext* ctx, AJ_ECCPublicKey* pub, AJ_ECCPrivateKey* prv)
{
    AJ_Status status;
    AJ_ECCSecret sec;
    AJ_SHA256_Context* sha;
    uint8_t* data;
    size_t size;

    // Generate shared secret
    status = AJ_GenerateShareSecret(pub, prv, &sec);
    if (AJ_OK != status) {
        return status;
    }

    size = AJ_SHA256_DIGEST_LENGTH;
    data = (uint8_t*) AJ_Malloc(size);
    if (NULL == data) {
        return AJ_ERR_RESOURCES;
    }
    sha = AJ_SHA256_Init();
    if (!sha) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    AJ_SHA256_Update(sha, sec.x, KEY_ECC_SZ);
    status = AJ_SHA256_Final(sha, data);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = ComputeMasterSecret(ctx, data, size);

Exit:
    AJ_Free(data);

    return status;
}

static AJ_Status ECDHEUnmarshalV3(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t* data;
    size_t size;
    AJ_ECCPublicKey pub;

    AJ_InfoPrintf(("ECDHEUnmarshalV3(ctx=%p, msg=%p)\n", ctx, msg));

    // Unmarshal the encoded key
    status = AJ_UnmarshalArgs(msg, "v", "(yay)", &pub.crv, &data, &size);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("ECDHEUnmarshalV3(ctx=%p, msg=%p): Unmarshal error\n", ctx, msg));
        return status;
    }
    if (KEY_CRV_NISTP256 != pub.crv) {
        AJ_InfoPrintf(("ECDHEUnmarshalV3(ctx=%p, msg=%p): Invalid curve\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    if (KEY_ECC_PUB_SZ != size) {
        AJ_InfoPrintf(("ECDHEUnmarshalV3(ctx=%p, msg=%p): Invalid key material\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }
    // Copy the public key
    memcpy(pub.x, data, KEY_ECC_SZ);
    memcpy(pub.y, data + KEY_ECC_SZ, KEY_ECC_SZ);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &pub.crv, sizeof (pub.crv));
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, data, size);

    status = GenerateShareSecret(ctx, &pub, &ctx->kectx.prv);

    return status;
}

static AJ_Status ECDHEUnmarshalV4(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    const char* variant;
    AJ_ECCPublicKey pub;

    AJ_InfoPrintf(("ECDHEUnmarshalV4(ctx=%p, msg=%p)\n", ctx, msg));

    // Unmarshal the encoded key
    status = AJ_UnmarshalVariant(msg, &variant);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("ECDHEUnmarshalV4(ctx=%p, msg=%p): Unmarshal error\n", ctx, msg));
        return status;
    }
    status = AJ_UnmarshalECCPublicKey(msg, &pub, NULL);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("ECDHEUnmarshalV4(ctx=%p, msg=%p): Unmarshal error\n", ctx, msg));
        return status;
    }

    status = GenerateShareSecret(ctx, &pub, &ctx->kectx.prv);

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

    switch (ctx->version >> 16) {
    case 1:
    case 2:
        status = ECDHEUnmarshalV1(ctx, msg);
        break;

    case 3:
        status = ECDHEUnmarshalV3(ctx, msg);
        break;

    case 4:
        status = ECDHEUnmarshalV4(ctx, msg);
        break;

    default:
        status = AJ_ERR_INVALID;
        break;
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
    if (0 != AJ_Crypto_Compare(local, remote, AUTH_VERIFIER_LEN)) {
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
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kactx.psk.hint, ctx->kactx.psk.hintSize);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, data, size);

    // CONVERSATION_V4 computes the PSK verifier based on these instead of including it in the conversation
    // hash, so save them for later.
    ctx->kactx.psk.key = data;
    ctx->kactx.psk.keySize = size;

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
            ctx->kactx.psk.hintSize = cred.len;
        }
        break;

    case AUTH_SERVER:
        cred.direction = AJ_CRED_RESPONSE;
        cred.data = ctx->kactx.psk.hint;
        cred.len = ctx->kactx.psk.hintSize;
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
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kactx.psk.hint, ctx->kactx.psk.hintSize);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, cred.data, cred.len);

    // CONVERSATION_V4 computes the PSK verifier based on these instead of including it in the conversation
    // hash, so save them for later.
    ctx->kactx.psk.key = cred.data;
    ctx->kactx.psk.keySize = cred.len;

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
        ctx->kactx.psk.hintSize = strlen(anon);
        status = PSKCallback(ctx, msg);
        if (AJ_OK != status) {
            return AJ_ERR_SECURITY;
        }
        status = ComputePSKVerifier(ctx, "client finished", verifier, sizeof (verifier));
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, verifier, sizeof (verifier));

        break;

    case AUTH_SERVER:
        status = ComputePSKVerifier(ctx, "server finished", verifier, sizeof (verifier));
        break;
    }
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }

    status = AJ_MarshalArgs(msg, "v", "(ayay)", ctx->kactx.psk.hint, ctx->kactx.psk.hintSize, verifier, sizeof (verifier));

    return status;
}

static AJ_Status PSKUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t verifier[AUTH_VERIFIER_LEN];
    uint8_t* data;
    size_t size;

    AJ_InfoPrintf(("PSKUnmarshal(ctx=%p, msg=%p)\n", ctx, msg));

    status = AJ_UnmarshalArgs(msg, "v", "(ayay)", &ctx->kactx.psk.hint, &ctx->kactx.psk.hintSize, &data, &size);
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    if (AUTH_VERIFIER_LEN != size) {
        return AJ_ERR_SECURITY;
    }

    switch (ctx->role) {
    case AUTH_CLIENT:
        status = ComputePSKVerifier(ctx, "server finished", verifier, sizeof (verifier));
        break;

    case AUTH_SERVER:
        status = PSKCallback(ctx, msg);
        if (AJ_OK != status) {
            return AJ_ERR_SECURITY;
        }
        status = ComputePSKVerifier(ctx, "client finished", verifier, sizeof (verifier));

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

    if (0 != AJ_Crypto_Compare(verifier, data, AUTH_VERIFIER_LEN)) {
        AJ_InfoPrintf(("PSKUnmarshal(ctx=%p, msg=%p): Invalid verifier\n", ctx, msg));
        return AJ_ERR_SECURITY;
    }

    return status;
}

/*
 * KeyAuthentication call expects yv = ya(ay)
 */
static AJ_Status MarshalCertificates(AJ_AuthenticationContext* ctx, X509CertificateChain* head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    uint8_t fmt = CERT_FMT_X509_DER;

    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &fmt, sizeof(fmt));
    status = AJ_MarshalArgs(msg, "y", fmt);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalVariant(msg, "a(ay)");
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (head) {
        status = AJ_MarshalArgs(msg, "(ay)", head->certificate.der.data, head->certificate.der.size);
        if (AJ_OK != status) {
            goto Exit;
        }
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, head->certificate.der.data, head->certificate.der.size);
        head = head->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

Exit:
    return status;
}

static AJ_Status ECDSAMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    AJ_ECCPrivateKey prv;
    AJ_ECCSignature sig;
    uint8_t verifier[AJ_SHA256_DIGEST_LENGTH];
    X509CertificateChain* chain = NULL;
    AJ_CredField field;

    AJ_InfoPrintf(("AJ_ECDSA_Marshal(ctx=%p, msg=%p)\n", ctx, msg));

    ctx->expiration = 0xFFFFFFFF;

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
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, sig.r, KEY_ECC_SZ);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, sig.s, KEY_ECC_SZ);

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
    status = AJ_X509ChainFromBuffer(&chain, &field);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = MarshalCertificates(ctx, chain, msg);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_ECDSA_Marshal(msg=%p): Marshal certificate chain error\n", msg));
        goto Exit;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

Exit:
    AJ_X509ChainFree(chain);
    AJ_CredFieldFree(&field);
    return status;
}

static AJ_Status ECDSAUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    const char* variant;
    uint8_t fmt;
    DER_Element der;
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
    ctx->kactx.ecdsa.num = 0;
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
            if (AJ_SHA256_DIGEST_LENGTH != node->certificate.tbs.extensions.digest.size) {
                AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Manifest digest invalid\n", msg));
                goto Exit;
            }
            /* Copy the manifest digest */
            memcpy((uint8_t*) &ctx->kactx.ecdsa.manifest, node->certificate.tbs.extensions.digest.data, AJ_SHA256_DIGEST_LENGTH);
        }
        /* Copy the public key */
        ctx->kactx.ecdsa.num++;
        ctx->kactx.ecdsa.key = (AJ_ECCPublicKey*) AJ_Realloc(ctx->kactx.ecdsa.key, ctx->kactx.ecdsa.num * sizeof (AJ_ECCPublicKey));
        if (NULL == ctx->kactx.ecdsa.key) {
            status = AJ_ERR_RESOURCES;
            goto Exit;
        }
        memcpy((uint8_t*) &ctx->kactx.ecdsa.key[ctx->kactx.ecdsa.num - 1], &node->certificate.tbs.publickey, sizeof (AJ_ECCPublicKey));
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

    /* Copy the public key (issuer) */
    ctx->kactx.ecdsa.num++;
    ctx->kactx.ecdsa.key = (AJ_ECCPublicKey*) AJ_Realloc(ctx->kactx.ecdsa.key, ctx->kactx.ecdsa.num * sizeof (AJ_ECCPublicKey));
    if (NULL == ctx->kactx.ecdsa.key) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    status = AJ_PolicyGetCAPublicKey(AJ_PEER_TYPE_FROM_CA, &head->certificate.tbs.extensions.aki, &ctx->kactx.ecdsa.key[ctx->kactx.ecdsa.num - 1]);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate authority unknown\n", msg));
        goto Exit;
    }
    /* Verify the chain */
    status = AJ_X509VerifyChain(head, &ctx->kactx.ecdsa.key[ctx->kactx.ecdsa.num - 1]);
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
    if (AJ_OK != status) {
        /* Free issuers */
        if (ctx->kactx.ecdsa.key) {
            AJ_Free(ctx->kactx.ecdsa.key);
            ctx->kactx.ecdsa.key = NULL;
            ctx->kactx.ecdsa.num = 0;
        }
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

uint8_t AJ_IsSuiteEnabled(AJ_BusAttachment* bus, uint32_t suite, uint32_t version)
{
    switch (suite) {
    case AUTH_SUITE_ECDHE_NULL:
        return 1 == bus->suites[0];

    case AUTH_SUITE_ECDHE_PSK:
        return 1 == bus->suites[1];

    case AUTH_SUITE_ECDHE_ECDSA:
        if (version < 3) {
            return 0;
        }
        return 1 == bus->suites[2];

    default:
        return 0;
    }

    return 0;
}

void AJ_EnableSuite(AJ_BusAttachment* bus, uint32_t suite)
{
    switch (suite) {
    case AUTH_SUITE_ECDHE_NULL:
        bus->suites[0] = 1;
        break;

    case AUTH_SUITE_ECDHE_PSK:
        bus->suites[1] = 1;
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        bus->suites[2] = 1;
        break;
    }
}

AJ_Status AJ_ConversationHash_Initialize(AJ_AuthenticationContext* ctx)
{
    ctx->hash = AJ_SHA256_Init();

    if (ctx->hash) {
        return AJ_OK;
    } else {
        AJ_ErrPrintf(("AJ_ConversationHash_Initialize() failed\n"));
        return AJ_ERR_RESOURCES;
    }
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

void AJ_ConversationHash_Update_UInt8(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, uint8_t byte)
{
    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }
    AJ_SHA256_Update(ctx->hash, &byte, sizeof(byte));
}

void AJ_ConversationHash_Update_UInt8Array(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const uint8_t* buf, size_t bufSize)
{
    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }
    if (conversationVersion >= CONVERSATION_V4) {
        uint8_t v_uintLE[sizeof(uint32_t)];
        AJ_ASSERT(bufSize <= 0xFFFFFFFF);
        uint32_t bufSizeU32 = (uint32_t)bufSize;
        HostU32ToLittleEndianU8(&bufSizeU32, sizeof(bufSizeU32), v_uintLE);
        AJ_SHA256_Update(ctx->hash, v_uintLE, sizeof(v_uintLE));
    }
    AJ_SHA256_Update(ctx->hash, buf, bufSize);
}

void AJ_ConversationHash_Update_String(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const char* str, size_t strSize)
{
    AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, (const uint8_t*)str, strSize);
}

void AJ_ConversationHash_Update_Message(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg, uint8_t isMarshaledMessage)
{
    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }

    AJ_ASSERT((0 == isMarshaledMessage) || (1 == isMarshaledMessage));

    AJ_ASSERT(!(msg->hdr->flags & AJ_FLAG_ENCRYPTED));

    if (1 == isMarshaledMessage) {
        /* msg->hdr->bodyLen gets set by AJ_DeliverMsg when the message is sent out. We set it here as well
         * so that the buffer we hash equals what will actually go out on the wire.
         */
        AJ_ASSERT(0 == msg->hdr->bodyLen);
        msg->hdr->bodyLen = msg->bodyBytes;
        AJ_ConversationHash_Update_UInt8Array(ctx,
                                              conversationVersion,
                                              msg->bus->sock.tx.bufStart,
                                              sizeof(AJ_MsgHeader) + msg->hdr->headerLen + HEADERPAD(msg->hdr->headerLen) + msg->hdr->bodyLen);
    } else {
        /* If the message hasn't already been unmarshaled, some data may still be waiting in the network
         * layer. AJ_ResetArgs will call AJ_SkipArg in a loop, which will unmarshal every argument and
         * ensure everything has been read into the message buffer, before resetting back to the beginning
         * of the message.
         */        
        AJ_Status status = AJ_ResetArgs(msg);
        if (AJ_OK != status) {
            AJ_AlwaysPrintf(("AJ_ConversationHash_Update_Message: Failed to reset msg %p; status is %s\n", msg, status));
            AJ_ASSERT(AJ_OK == status); /* This shouldn't happen; always break in debug builds. */
            return;
        }
        /* When a message is received, the AJ_FLAG_AUTO_START bit is flipped during unmarshaling.
         * In thin client, because the AJ_Message data structures are overlaid on the raw buffer, this
         * changes the buffer's content as well. Undo this flip so we hash the actual on-wire contents,
         * hash, and then put it back. See AJ_UnmarshalMsg.
         */
        msg->hdr->flags ^= AJ_FLAG_AUTO_START;
        AJ_ConversationHash_Update_UInt8Array(ctx,
                                              conversationVersion,
                                              msg->bus->sock.rx.bufStart,
                                              sizeof(AJ_MsgHeader) + msg->hdr->headerLen + HEADERPAD(msg->hdr->headerLen) + msg->hdr->bodyLen);
        msg->hdr->flags ^= AJ_FLAG_AUTO_START;
    }

}

AJ_Status AJ_ConversationHash_GetDigest(AJ_AuthenticationContext* ctx, uint8_t* digest)
{
    return AJ_SHA256_GetDigest(ctx->hash, digest);
}

AJ_Status AJ_ConversationHash_Reset(AJ_AuthenticationContext* ctx)
{
    AJ_Status status;

    status = AJ_SHA256_Final(ctx->hash, NULL);

    if (status == AJ_OK) {
        status = AJ_ConversationHash_Initialize(ctx);
    }

    return status;
}
