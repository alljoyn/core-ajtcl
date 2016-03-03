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
#include <ajtcl/aj_conversationhash.h>

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

    AJ_ASSERT(len <= UINT8_MAX);

    AJ_InfoPrintf(("ComputeMasterSecret(ctx=%p, pms=%p, len=%u)\n", ctx, pms, (uint32_t)len));

    data[0] = pms;
    lens[0] = (uint8_t) len;
    data[1] = (uint8_t*) "master secret";
    lens[1] = 13;

    return AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), ctx->mastersecret, AJ_MASTER_SECRET_LEN);
}

static AJ_Status ComputeVerifier(AJ_AuthenticationContext* ctx, const char* label, uint8_t* buffer, size_t bufferlen)
{
    const uint8_t* data[3];
    uint8_t lens[3];

    AJ_ASSERT(bufferlen <= UINT32_MAX);

    data[0] = ctx->mastersecret;
    lens[0] = AJ_MASTER_SECRET_LEN;
    data[1] = (uint8_t*) label;
    lens[1] = (uint8_t) strlen(label);
    data[2] = ctx->digest;
    lens[2] = (uint8_t) sizeof (ctx->digest);

    return AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), buffer, (uint32_t) bufferlen);
}

static AJ_Status ComputePSKVerifier(AJ_AuthenticationContext* ctx, const char* label, uint8_t* buffer, size_t bufferlen)
{
    const uint8_t* data[5];
    uint8_t lens[5];

    /* Use the old method for < CONVERSATION_V4. */
    if (AJ_UNPACK_AUTH_VERSION(ctx->version) < CONVERSATION_V4) {
        return ComputeVerifier(ctx, label, buffer, bufferlen);
    }

    data[0] = ctx->mastersecret;
    lens[0] = AJ_MASTER_SECRET_LEN;
    data[1] = (uint8_t*)label;
    lens[1] = (uint8_t)strlen(label);
    data[2] = ctx->digest;
    lens[2] = sizeof(ctx->digest);
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
    AJ_Credential cred = { 0 };

    AJ_InfoPrintf(("ECDHEMarshal(ctx=%p, msg=%p)\n", ctx, msg));

    // Generate key pair if client
    if (AUTH_CLIENT == ctx->role) {

        if (ctx->suite == AUTH_SUITE_ECDHE_SPEKE) { /* EC-SPEKE keygen depends on the password, use the callback */

            if (ctx->bus->authListenerCallback == NULL) {
                AJ_InfoPrintf(("Authentication failure: Missing callback for ECDHE_SPEKE\n"));
                return AJ_ERR_INVALID;
            }

            status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_SPEKE, AJ_CRED_PASSWORD, &cred);
            if (status != AJ_OK) {
                AJ_InfoPrintf(("Authentication failure: callback failed for ECDHE_SPEKE\n"));
                return status;
            }

            if (cred.expiration) {
                ctx->expiration = cred.expiration;
            }

            status = AJ_GenerateSPEKEKeyPair(cred.data, cred.len, &ctx->kactx.speke.localGUID, ctx->kactx.speke.remoteGUID,
                                             &ctx->kectx.pub, &ctx->kectx.prv);
        } else {   /* The other ECDH suites use traditional key generation */
            status = AJ_GenerateECCKeyPair(&ctx->kectx.pub, &ctx->kectx.prv);
        }

        if (AJ_OK != status) {
            AJ_InfoPrintf(("ECDHEMarshal(ctx=%p, msg=%p): Key generation failed\n", ctx, msg));
            return status;
        }
    }

    switch (AJ_UNPACK_AUTH_VERSION(ctx->version)) {
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
    AJ_Credential cred = { 0 };

    AJ_InfoPrintf(("ECDHEUnmarshal(ctx=%p, msg=%p)\n", ctx, msg));

    // Generate key pair if server
    if (AUTH_SERVER == ctx->role) {
        if (ctx->suite == AUTH_SUITE_ECDHE_SPEKE) { /* EC-SPEKE keygen depends on the password, use the callback */

            if (ctx->bus->authListenerCallback == NULL) {
                AJ_InfoPrintf(("Authentication failure: Missing callback for ECDHE_SPEKE\n"));
                return AJ_ERR_INVALID;
            }

            status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_SPEKE, AJ_CRED_PASSWORD, &cred);
            if (status != AJ_OK) {
                AJ_InfoPrintf(("Authentication failure: callback failed for ECDHE_SPEKE\n"));
                return status;
            }

            if (cred.expiration) {
                ctx->expiration = cred.expiration;
            }

            status = AJ_GenerateSPEKEKeyPair(cred.data, cred.len, ctx->kactx.speke.remoteGUID, &ctx->kactx.speke.localGUID,
                                             &ctx->kectx.pub, &ctx->kectx.prv);
        } else {   /* The other ECDH suites use traditional key generation */
            status = AJ_GenerateECCKeyPair(&ctx->kectx.pub, &ctx->kectx.prv);
        }

        if (AJ_OK != status) {
            AJ_InfoPrintf(("ECDHEUnmarshal(ctx=%p, msg=%p): Key generation failed\n", ctx, msg));
            return status;
        }
    }

    switch (AJ_UNPACK_AUTH_VERSION(ctx->version)) {
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

static AJ_Status PSKSetHint(AJ_AuthenticationContext* ctx, const uint8_t* hint, size_t hintSize)
{
    AJ_ASSERT(((NULL == ctx->kactx.psk.hint) && (ctx->kactx.psk.hintSize == 0)) ||
              ((NULL != ctx->kactx.psk.hint) && (ctx->kactx.psk.hintSize > 0)));
    AJ_Free(ctx->kactx.psk.hint);

    ctx->kactx.psk.hint = AJ_Malloc(hintSize);
    if (NULL == ctx->kactx.psk.hint) {
        ctx->kactx.psk.hintSize = 0;
        return AJ_ERR_RESOURCES;
    }
    ctx->kactx.psk.hintSize = hintSize;
    memcpy(ctx->kactx.psk.hint, hint, hintSize);

    return AJ_OK;
}

static AJ_Status PSKSetKey(AJ_AuthenticationContext* ctx, const uint8_t* key, size_t keySize)
{
    if (NULL != ctx->kactx.psk.key) {
        AJ_ASSERT(ctx->kactx.psk.keySize > 0);
        AJ_MemZeroSecure(ctx->kactx.psk.key, ctx->kactx.psk.keySize);
        AJ_Free(ctx->kactx.psk.key);
    }

    ctx->kactx.psk.key = AJ_Malloc(keySize);
    if (NULL == ctx->kactx.psk.key) {
        ctx->kactx.psk.keySize = 0;
        return AJ_ERR_RESOURCES;
    }
    ctx->kactx.psk.keySize = keySize;
    memcpy(ctx->kactx.psk.key, key, keySize);

    return AJ_OK;
}

static AJ_Status PSKCallbackV1(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    uint8_t data[PSK_V1_CALLBACK_BUFFER_SIZE];
    size_t size = sizeof (data);

    /*
     * Assume application does not copy in more than this size buffer
     * Expiration not set by application
     */
    size = ctx->bus->pwdCallback(data, (uint32_t)size);
    if (sizeof (data) < size) {
        AJ_MemZeroSecure(data, sizeof(data));
        return AJ_ERR_RESOURCES;
    }
    status = PSKSetKey(ctx, data, size);
    AJ_MemZeroSecure(data, sizeof (data));
    if (AJ_OK != status) {
        return status;
    }
    ctx->expiration = 0xFFFFFFFF;
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kactx.psk.hint, ctx->kactx.psk.hintSize);
    /* Calling AJ_ConversationHash_SetSensitiveMode ensures the PSK won't end up in the log if conversation
     * hash tracing is turned on.
     */
    AJ_ConversationHash_SetSensitiveMode(ctx, TRUE);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kactx.psk.key, ctx->kactx.psk.keySize);
    AJ_ConversationHash_SetSensitiveMode(ctx, FALSE);
    if (AJ_UNPACK_AUTH_VERSION(ctx->version) < CONVERSATION_V4) {
        status = AJ_ConversationHash_GetDigest(ctx);
    }

    return status;
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
            status = PSKSetHint(ctx, cred.data, cred.len);
        }
        break;

    case AUTH_SERVER:
        cred.direction = AJ_CRED_RESPONSE;
        cred.data = ctx->kactx.psk.hint;
        cred.len = ctx->kactx.psk.hintSize;
        status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PUB_KEY, &cred);
        break;
    }
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    cred.direction = AJ_CRED_REQUEST;
    status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PRV_KEY, &cred);
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    ctx->expiration = cred.expiration;
    // Hash in psk hint, then psk
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, ctx->kactx.psk.hint, ctx->kactx.psk.hintSize);
    /* Calling AJ_ConversationHash_SetSensitiveMode ensures the PSK won't end up in the log if conversation
     * hash tracing is turned on.
     */
    AJ_ConversationHash_SetSensitiveMode(ctx, TRUE);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, cred.data, cred.len);
    AJ_ConversationHash_SetSensitiveMode(ctx, FALSE);
    if (AJ_UNPACK_AUTH_VERSION(ctx->version) < CONVERSATION_V4) {
        status = AJ_ConversationHash_GetDigest(ctx);
        if (AJ_OK != status) {
            return status;
        }
    }

    // CONVERSATION_V4 computes the PSK verifier based on these instead of including it in the conversation
    // hash, so save them for later.
    status = PSKSetKey(ctx, cred.data, cred.len);

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
        status = PSKSetHint(ctx, (const uint8_t*) anon, strlen(anon));
        if (AJ_OK != status) {
            return AJ_ERR_SECURITY;
        }
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
    uint8_t* hint;
    size_t hintSize;
    uint8_t* data;
    size_t size;

    AJ_InfoPrintf(("PSKUnmarshal(ctx=%p, msg=%p)\n", ctx, msg));

    status = AJ_UnmarshalArgs(msg, "v", "(ayay)", &hint, &hintSize, &data, &size);
    if (AJ_OK != status) {
        return AJ_ERR_SECURITY;
    }
    if (AUTH_VERIFIER_LEN != size) {
        return AJ_ERR_SECURITY;
    }
    status = PSKSetHint(ctx, hint, hintSize);
    if (AJ_OK != status) {
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
static AJ_Status MarshalCertificates(AJ_AuthenticationContext* ctx, X509CertificateChain* root, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    X509CertificateChain* head;
    uint8_t fmt = CERT_FMT_X509_DER;

    /*
     * X509CertificateChain is root first.
     * The wire protocol requires leaf first,
     * reverse it here, then reverse it back after marshalling.
     */
    root = AJ_X509ReverseChain(root);
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
    head = root;
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
    root = AJ_X509ReverseChain(root);
    return status;
}

static AJ_Status ECDSAMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    AJ_ECCPrivateKey prv;
    AJ_ECCSignature sig;
    uint8_t verifier[AJ_SHA256_DIGEST_LENGTH];
    X509CertificateChain* root = NULL;
    AJ_CredField field;
    uint8_t owns_data = FALSE;
    AJ_Credential cred;

    AJ_InfoPrintf(("ECDSAMarshal(ctx=%p, msg=%p)\n", ctx, msg));

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

    /* Get certificate chain from keystore */
    status = AJ_CredentialGet(AJ_CERTIFICATE_IDN_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &field);
    if (AJ_OK == status) {
        status = AJ_X509ChainFromBuffer(&root, &field);
        if (AJ_OK != status) {
            goto Exit;
        }
        owns_data = TRUE;
        /* Get private key from keystore */
        status = AJ_CredentialGetECCPrivateKey(AJ_ECC_SIG, NULL, NULL, &prv);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("ECDSAMarshal(ctx=%p, msg=%p): Private key missing\n", ctx, msg));
            goto Exit;
        }
    } else if (NULL != ctx->bus->authListenerCallback) {
        /* Get certificate chain from application */
        cred.direction = AJ_CRED_REQUEST;
        status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_ECDSA, AJ_CRED_CERT_CHAIN, &cred);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("ECDSAMarshal(ctx=%p, msg=%p): certificate chain missing\n", ctx, msg));
            goto Exit;
        }
        root = (X509CertificateChain*) cred.data;
        /* Get private key from application */
        cred.direction = AJ_CRED_REQUEST;
        cred.len = sizeof (AJ_ECCPrivateKey);
        cred.data = (uint8_t*) &prv;
        status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_ECDSA, AJ_CRED_PRV_KEY, &cred);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("ECDSAMarshal(ctx=%p, msg=%p): Private key missing\n", ctx, msg));
            goto Exit;
        }
    }
    if (AJ_OK != status) {
        AJ_WarnPrintf(("ECDSAMarshal(ctx=%p, msg=%p): certificate chain missing\n", ctx, msg));
        goto Exit;
    }

    /* Sign verifier */
    status = AJ_ECDSASignDigest(verifier, &prv, &sig);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("ECDSAMarshal(ctx=%p, msg=%p): Sign verifier error\n", ctx, msg));
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

    /* Marshal certificate chain */
    status = MarshalCertificates(ctx, root, msg);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("ECDSAMarshal(ctx=%p, msg=%p): Marshal certificate chain error\n", ctx, msg));
        goto Exit;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

Exit:
    if (owns_data) {
        AJ_X509ChainFree(root);
    }
    AJ_CredFieldFree(&field);
    return status;
}

static AJ_Status ECDSAUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg, uint32_t version)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    AJ_SHA256_Context* thumbprintHashCtx;
    const char* variant;
    uint8_t fmt;
    DER_Element der;
    AJ_ECCPublicKey pub;
    AJ_ECCSignature sig;
    uint8_t* sig_r;
    uint8_t* sig_s;
    size_t len_r;
    size_t len_s;
    X509CertificateChain* root = NULL;
    X509CertificateChain* node = NULL;
    AJ_Credential cred;
    uint8_t trusted = 0;
    uint32_t type;

    AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p)\n", ctx, msg));

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
        status = AJ_ERR_SECURITY;
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
        status = AJ_ERR_SECURITY;
        goto Exit;
    }
    if ((KEY_ECC_SZ != len_r) || (KEY_ECC_SZ != len_s)) {
        status = AJ_ERR_SECURITY;
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
        AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): DER encoding expected\n", ctx, msg));
        status = AJ_ERR_SECURITY;
        goto Exit;
    }
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V1, &fmt, sizeof(fmt));
    status = AJ_UnmarshalVariant(msg, &variant);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (0 != strncmp(variant, "a(ay)", 5)) {
        status = AJ_ERR_SECURITY;
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
            AJ_WarnPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Resource error\n", ctx, msg));
            status = AJ_ERR_RESOURCES;
            goto Exit;
        }
        /*
         * Push the certificate on to the front of the chain.
         * We do this before decoding so that it is cleaned up in case of error.
         */
        node->next = root;
        root = node;
        /* Set the der before its consumed */
        node->certificate.der.size = der.size;
        node->certificate.der.data = der.data;
        status = AJ_X509DecodeCertificateDER(&node->certificate, &der);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Certificate decode failed\n", ctx, msg));
            goto Exit;
        }

        /*
         * If this is the first certificate, check that it signed the verifier
         * Also save the subject public key and thumbprint for authorisation check
         */
        if (NULL == node->next) {
            status = AJ_ECDSAVerifyDigest(digest, &sig, &node->certificate.tbs.publickey);
            if (AJ_OK != status) {
                AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Signature invalid\n", ctx, msg));
                goto Exit;
            }
            thumbprintHashCtx = AJ_SHA256_Init();
            if (!thumbprintHashCtx) {
                AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Could not allocate SHA256 context\n", ctx, msg));
                goto Exit;
            }
            AJ_SHA256_Update(thumbprintHashCtx, node->certificate.der.data, node->certificate.der.size);
            status = AJ_SHA256_Final(thumbprintHashCtx, ctx->kactx.ecdsa.thumbprint);
            if (AJ_OK != status) {
                AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Got status %u from AJ_SHA256_Final\n", ctx, msg, status));
                goto Exit;
            }
            ctx->kactx.ecdsa.thumbprintSize = AJ_SHA256_DIGEST_LENGTH;
        }
        /* Copy the public key */
        ctx->kactx.ecdsa.num++;
        ctx->kactx.ecdsa.key = (AJ_ECCPublicKey*) AJ_Realloc(ctx->kactx.ecdsa.key, ctx->kactx.ecdsa.num * sizeof (AJ_ECCPublicKey));
        if (NULL == ctx->kactx.ecdsa.key) {
            status = AJ_ERR_RESOURCES;
            goto Exit;
        }
        memcpy(&ctx->kactx.ecdsa.key[ctx->kactx.ecdsa.num - 1], &node->certificate.tbs.publickey, sizeof (AJ_ECCPublicKey));
    }
    if (AJ_ERR_NO_MORE != status) {
        AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Certificate chain error %s\n", ctx, msg, AJ_StatusText(status)));
        status = AJ_ERR_SECURITY;
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
    if (NULL == root) {
        AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Certificate chain missing\n", ctx, msg));
        status = AJ_ERR_SECURITY;
        goto Exit;
    }

    /* Initial chain verification to validate intermediate issuers.
     * Type is ignored for auth version < 4.
     */
    if (AJ_UNPACK_AUTH_VERSION(version) < CONVERSATION_V4) {
        type = 0;
    } else {
        type = AJ_CERTIFICATE_IDN_X509;
    }
    status = AJ_X509VerifyChain(root, NULL, type);
    if (AJ_OK == status) {
        /* Verify the root certificate against the stored authorities */
        status = AJ_PolicyVerifyCertificate(&root->certificate, &pub);
        if (AJ_OK == status) {
            /* Copy the public key (issuer) */
            ctx->kactx.ecdsa.num++;
            ctx->kactx.ecdsa.key = (AJ_ECCPublicKey*) AJ_Realloc(ctx->kactx.ecdsa.key, ctx->kactx.ecdsa.num * sizeof (AJ_ECCPublicKey));
            if (NULL == ctx->kactx.ecdsa.key) {
                status = AJ_ERR_RESOURCES;
                goto Exit;
            }
            memcpy(&ctx->kactx.ecdsa.key[ctx->kactx.ecdsa.num - 1], &pub, sizeof (pub));
        } else {
            /* Search for the intermediate issuers in the stored authorities */
            status = AJ_PolicyFindAuthority(root);
        }
        if (AJ_OK == status) {
            trusted = 1;
        }

        /* Last resort, ask the application to verify the chain */
        if (!trusted && (NULL != ctx->bus->authListenerCallback)) {
            AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Certificate authority unknown\n", ctx, msg));
            /* Ask the application to verify the chain */
            cred.direction = AJ_CRED_RESPONSE;
            cred.data = (uint8_t*) root;
            status = ctx->bus->authListenerCallback(AUTH_SUITE_ECDHE_ECDSA, AJ_CRED_CERT_CHAIN, &cred);
            if (AJ_OK != status) {
                AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Certificate chain rejected by app\n", ctx, msg));
                goto Exit;
            }
            trusted = 1;
        }
    } else {
        AJ_InfoPrintf(("ECDSAUnmarshal(ctx=%p, msg=%p): Certificate chain invalid\n", ctx, msg));
    }

Exit:
    /* Free the cert chain */
    while (root) {
        node = root;
        root = root->next;
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

    case AUTH_SUITE_ECDHE_SPEKE:        /* Same marshalling as ECDHE_NULL. */
        status = NULLMarshal(ctx, msg);
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
        status = ECDSAUnmarshal(ctx, msg, ctx->version);
        break;

    case AUTH_SUITE_ECDHE_SPEKE:        /* Same unmarshalling as ECDHE_NULL. */
        status = NULLUnmarshal(ctx, msg);
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

    case AUTH_SUITE_ECDHE_SPEKE:
        return 1 == bus->suites[3];

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

    case AUTH_SUITE_ECDHE_SPEKE:
        bus->suites[3] = 1;
        break;
    }
}

