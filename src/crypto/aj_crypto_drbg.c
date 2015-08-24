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
#define AJ_MODULE CRYPTO_DRBG

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_aes_priv.h>
#include <ajtcl/aj_crypto_drbg.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_config.h>
/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCRYPTO_DRBG = 0;
#endif

/*
 * CTR DRBG is implemented using algorithms described in the
 * NIST SP 800-90A standard, which can be found at
 * http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
 */

static void AES_CTR_DRBG_Increment(uint8_t* data, size_t size)
{
    while (size--) {
        data[size]++;
        if (data[size]) {
            break;
        }
    }
}

static void AES_CTR_DRBG_Update(CTR_DRBG_CTX* ctx, uint8_t data[SEEDLEN])
{
    size_t i = 0;
    uint8_t tmp[SEEDLEN];
    uint8_t* t = tmp;

    AJ_AES_Enable(ctx->k);
    for (i = 0; i < SEEDLEN; i += OUTLEN) {
        AES_CTR_DRBG_Increment(ctx->v, OUTLEN);
        AJ_AES_ECB_128_ENCRYPT(ctx->k, ctx->v, t);
        t += OUTLEN;
    }

    for (i = 0; i < SEEDLEN; i++) {
        tmp[i] ^= data[i];
    }

    memcpy(ctx->k, tmp, KEYLEN);
    memcpy(ctx->v, tmp + KEYLEN, OUTLEN);
}

static void AES_CTR_DRBG_BCC(uint8_t* k, uint8_t* data, size_t size, uint8_t* out)
{
    size_t i;
    size_t j;

    AJ_ASSERT(0 == (size % OUTLEN));
    memset(out, 0, OUTLEN);

    AJ_AES_Enable(k);
    for (i = 0; i < size; i += OUTLEN) {
        for (j = 0; j < OUTLEN; j++) {
            out[j] ^= data[j];
        }
        AJ_AES_ECB_128_ENCRYPT(k, out, out);
        data += OUTLEN;
    }
}

static void AES_CTR_DRBG_DF(uint8_t* seed, size_t size, uint8_t data[SEEDLEN])
{
    // Variable names reflect NIST SP 800-90A
    uint32_t i = 0;
    uint32_t L = size;
    uint32_t N = SEEDLEN;
    uint32_t n = OUTLEN + sizeof (L) + sizeof (N) + size + sizeof (0x80);
    uint8_t* S;
    uint8_t* s;
    uint8_t k[KEYLEN];
    uint8_t K[KEYLEN];
    uint8_t X[KEYLEN];

    n += (OUTLEN - (n % OUTLEN));
    AJ_ASSERT(0 == (n % OUTLEN));
    S = AJ_Malloc(n);
    if (NULL == S) {
        // Errors are not propagated up
        return;
    }

    memset(S, 0, n);
    s = S + OUTLEN;
    *s++ = (L >> 24) & 0xFF;
    *s++ = (L >> 16) & 0xFF;
    *s++ = (L >>  8) & 0xFF;
    *s++ = (L >>  0) & 0xFF;
    *s++ = (N >> 24) & 0xFF;
    *s++ = (N >> 16) & 0xFF;
    *s++ = (N >>  8) & 0xFF;
    *s++ = (N >>  0) & 0xFF;
    memcpy(s, seed, size);
    s += size;
    *s++ = 0x80;

    for (i = 0; i < KEYLEN; i++) {
        k[i] = i;
    }

    AES_CTR_DRBG_BCC(k, S, n, K);
    AES_CTR_DRBG_Increment(S, 4);
    AES_CTR_DRBG_BCC(k, S, n, X);

    AJ_AES_Enable(K);
    AJ_AES_ECB_128_ENCRYPT(K, X, X);
    memcpy(data, X, OUTLEN);
    data += OUTLEN;
    AJ_AES_ECB_128_ENCRYPT(K, X, X);
    memcpy(data, X, OUTLEN);

    AJ_Free(S);
}

void AES_CTR_DRBG_Reseed(CTR_DRBG_CTX* ctx, uint8_t* seed, size_t size)
{
    uint8_t data[SEEDLEN];
    if (ctx->df) {
        AES_CTR_DRBG_DF(seed, size, data);
        AES_CTR_DRBG_Update(ctx, data);
    } else {
        AJ_ASSERT(SEEDLEN == size);
        AES_CTR_DRBG_Update(ctx, seed);
    }
    ctx->c = 1;
}

void AES_CTR_DRBG_Instantiate(CTR_DRBG_CTX* ctx, uint8_t* seed, size_t size, uint8_t df)
{
    memset(ctx->k, 0, KEYLEN);
    memset(ctx->v, 0, OUTLEN);
    ctx->df = df;
    AES_CTR_DRBG_Reseed(ctx, seed, size);
}

AJ_Status AES_CTR_DRBG_Generate(CTR_DRBG_CTX* ctx, uint8_t* randBuf, size_t size)
{
    uint8_t data[SEEDLEN];
    size_t copy;

    // Reseed interval 2^32 (counter wraps to zero)
    if (0 == ctx->c) {
        return AJ_ERR_SECURITY;
    }
    AJ_AES_Enable(ctx->k);
    while (size) {
        AES_CTR_DRBG_Increment(ctx->v, OUTLEN);
        AJ_AES_ECB_128_ENCRYPT(ctx->k, ctx->v, data);
        copy = (size < OUTLEN) ? size : OUTLEN;
        memcpy(randBuf, data, copy);
        randBuf += copy;
        size -= copy;
    }
    memset(data, 0, SEEDLEN);
    AES_CTR_DRBG_Update(ctx, data);
    ctx->c++;

    return AJ_OK;
}

