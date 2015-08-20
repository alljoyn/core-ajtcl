/**
 * @file aj_crypto_sha2.c
 *
 * Class for SHA-256
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
#define AJ_MODULE CRYPTO_SHA2

#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_sha2.h>
#include <ajtcl/aj_util.h>
#include <sha2.h>
#include <ajtcl/aj_debug.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCRYPTO_SHA2 = 0;
#endif

#if AJ_SHA256_DIGEST_LENGTH != SHA256_DIGEST_LENGTH
#error Digest length mismatch
#endif

#define HMAC_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define HMAC_SHA256_BLOCK_LENGTH  64

struct AJ_SHA256_Context {
    SHA256_CTX internal;
};

typedef struct _AJ_HMAC_SHA256_CTX {
    uint8_t ipad[HMAC_SHA256_BLOCK_LENGTH];
    uint8_t opad[HMAC_SHA256_BLOCK_LENGTH];
    AJ_SHA256_Context* hashCtx;
} AJ_HMAC_SHA256_CTX;

static AJ_Status AJ_HMAC_SHA256_Init(AJ_HMAC_SHA256_CTX* ctx, const uint8_t* key, size_t keyLen);

static void AJ_HMAC_SHA256_Update(AJ_HMAC_SHA256_CTX* ctx, const uint8_t* data, size_t dataLen);

static AJ_Status AJ_HMAC_SHA256_Final(AJ_HMAC_SHA256_CTX* ctx, uint8_t* digest);

/**
 * Initialize the hash context.  Calls to this function must be
 * matched with a call to AJ_SHA256_Final() to ensure that resources
 * are released.
 *
 * @return Pointer to context. NULL if init failed.
 */
AJ_SHA256_Context* AJ_SHA256_Init(void)
{
    AJ_SHA256_Context* context;
    context = AJ_Malloc(sizeof(*context));
    if (context) {
        SHA256_Init(&context->internal);
    } else {
        AJ_ErrPrintf(("SHA256 context allocation failure\n"));
    }
    return context;
}

/**
 * Update the digest using the specific bytes
 * @param context the hash context
 * @param buf the bytes to digest
 * @param bufSize the number of bytes to digest
 */
void AJ_SHA256_Update(AJ_SHA256_Context* context, const uint8_t* buf, size_t bufSize) {
    SHA256_Update(&context->internal, buf, bufSize);
}

/**
 * Retrieve the digest
 * @param context the hash context
 * @param digest the buffer to hold the digest.  Must be of size AJ_SHA256_DIGEST_LENGTH
 * @param keepAlive keep the digest process alive for continuing digest
 * @return AJ_OK if successful, otherwise error.
 */
static AJ_Status getDigest(AJ_SHA256_Context* context, uint8_t* digest,
                           const uint8_t keepAlive) {
    AJ_SHA256_Context tempCtx;
    AJ_SHA256_Context* finalCtx;

    if (keepAlive) {
        memcpy(&tempCtx, context, sizeof(AJ_SHA256_Context));
        finalCtx = &tempCtx;
    } else {
        finalCtx = context;
    }

    SHA256_Final(digest, &finalCtx->internal);
    AJ_MemZeroSecure(finalCtx, sizeof(*finalCtx));

    if (!keepAlive) {
        AJ_Free(context);
    }

    return AJ_OK;
}

/**
 * Retrieve the digest but keep the hash active for further updates.
 * @param context the hash context
 * @param digest the buffer to hold the digest.  Must be of size AJ_SHA256_DIGEST_LENGTH
 * @return AJ_OK if successful, otherwise error.
 */
AJ_Status AJ_SHA256_GetDigest(AJ_SHA256_Context* context, uint8_t* digest)
{
    return getDigest(context, digest, 1);
}

/**
 * Finish the hash calculation and free resources.
 * @param context the hash context
 * @param digest - the buffer to hold the digest.
 *        Must be NULL or of size AJ_SHA256_DIGEST_LENGTH.
 *        If the value is NULL, resources are freed but the digest
 *        is not calculated.
 * @return AJ_OK if successful, otherwise error.
 */
AJ_Status AJ_SHA256_Final(AJ_SHA256_Context* context, uint8_t* digest)
{
    AJ_Status status = AJ_OK;

    if (!digest) {
        AJ_MemZeroSecure(context, sizeof(*context));
        AJ_Free(context);
    } else {
        status = getDigest(context, digest, 0);
    }
    return status;
}

/**
 * Initialize the HMAC context
 * @param ctx the HMAC context
 * @param key the key
 * @param keyLen the length of the key
 * @return
 *  - AJ_OK if successful
 *  - AJ_ERR_INVALID if the length is negative
 */
static AJ_Status AJ_HMAC_SHA256_Init(AJ_HMAC_SHA256_CTX* ctx, const uint8_t* key, size_t keyLen)
{
    int cnt;

    memset(ctx->ipad, 0, HMAC_SHA256_BLOCK_LENGTH);
    memset(ctx->opad, 0, HMAC_SHA256_BLOCK_LENGTH);
    /* if keyLen > 64, hash it and use it as key */
    if (keyLen > HMAC_SHA256_BLOCK_LENGTH) {
        uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
        AJ_Status status;
        ctx->hashCtx = AJ_SHA256_Init();
        if (!ctx->hashCtx) {
            return AJ_ERR_RESOURCES;
        }
        AJ_SHA256_Update(ctx->hashCtx, key, keyLen);
        status = AJ_SHA256_Final(ctx->hashCtx, digest);
        if (status != AJ_OK) {
            return status;
        }
        keyLen = AJ_SHA256_DIGEST_LENGTH;
        memcpy(ctx->ipad, digest, AJ_SHA256_DIGEST_LENGTH);
        memcpy(ctx->opad, digest, AJ_SHA256_DIGEST_LENGTH);
    } else {
        memcpy(ctx->ipad, key, keyLen);
        memcpy(ctx->opad, key, keyLen);
    }
    /*
     * the HMAC_SHA256 process
     *
     * SHA256(K XOR opad, SHA256(K XOR ipad, msg))
     *
     * K is the key
     * ipad is filled with 0x36
     * opad is filled with 0x5c
     * msg is the message
     */

    /*
     * prepare inner hash SHA256(K XOR ipad, msg)
     * K XOR ipad
     */
    for (cnt = 0; cnt < HMAC_SHA256_BLOCK_LENGTH; cnt++) {
        ctx->ipad[cnt] ^= 0x36;
    }

    ctx->hashCtx = AJ_SHA256_Init();
    if (!ctx->hashCtx) {
        return AJ_ERR_RESOURCES;
    }

    AJ_SHA256_Update(ctx->hashCtx, ctx->ipad, HMAC_SHA256_BLOCK_LENGTH);
    return AJ_OK;
}

/**
 * Update the hash with data
 * @param ctx the HMAC context
 * @param data the data
 * @param dataLen the length of the data
 * @return
 *  - AJ_OK if successful
 *  - AJ_ERR_INVALID if the length is negative
 */
static void AJ_HMAC_SHA256_Update(AJ_HMAC_SHA256_CTX* ctx, const uint8_t* data, size_t dataLen)
{
    AJ_SHA256_Update(ctx->hashCtx, data, dataLen);
}

/**
 * Retrieve the final digest for the HMAC
 * @param ctx the HMAC context
 * @param digest the buffer to hold the digest.  Must be of size AJ_SHA256_DIGEST_LENGTH
 */
static AJ_Status AJ_HMAC_SHA256_Final(AJ_HMAC_SHA256_CTX* ctx, uint8_t* digest)
{
    int cnt;
    AJ_Status status;

    /* complete inner hash SHA256(K XOR ipad, msg) */
    status = AJ_SHA256_Final(ctx->hashCtx, digest);
    if (status != AJ_OK) {
        return status;
    }

    /*
     * perform outer hash SHA256(K XOR opad, SHA256(K XOR ipad, msg))
     */
    for (cnt = 0; cnt < HMAC_SHA256_BLOCK_LENGTH; cnt++) {
        ctx->opad[cnt] ^= 0x5c;
    }
    ctx->hashCtx = AJ_SHA256_Init();
    if (!ctx->hashCtx) {
        return AJ_ERR_RESOURCES;
    }
    AJ_SHA256_Update(ctx->hashCtx, ctx->opad, HMAC_SHA256_BLOCK_LENGTH);
    AJ_SHA256_Update(ctx->hashCtx, digest, AJ_SHA256_DIGEST_LENGTH);
    status = AJ_SHA256_Final(ctx->hashCtx, digest);
    return status;
}

AJ_Status AJ_Crypto_PRF_SHA256(const uint8_t** inputs, const uint8_t* lengths,
                               uint32_t count, uint8_t* out, uint32_t outLen)
{
    uint32_t cnt;
    AJ_HMAC_SHA256_CTX msgHash;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    uint32_t len = 0;
    AJ_Status status;

    if (count < 2) {
        return AJ_ERR_INVALID;
    }
    while (outLen) {
        /*
         * Initialize SHA256 in HMAC mode with the secret
         */
        status = AJ_HMAC_SHA256_Init(&msgHash, inputs[0], lengths[0]);
        if (status != AJ_OK) {
            return status;
        }
        /*
         * If this is not the first iteration hash in the digest from the previous iteration.
         */
        if (len) {
            AJ_HMAC_SHA256_Update(&msgHash, digest, sizeof(digest));
        }
        for (cnt = 1; cnt < count; cnt++) {
            AJ_HMAC_SHA256_Update(&msgHash, inputs[cnt], lengths[cnt]);
        }
        AJ_HMAC_SHA256_Final(&msgHash, digest);
        if (outLen < sizeof(digest)) {
            len = outLen;
        } else {
            len = sizeof(digest);
        }
        memcpy(out, digest, len);
        outLen -= len;
        out += len;
    }

    return AJ_OK;
}
