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
#define AJ_MODULE CRYPTO

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_aes_priv.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_config.h>


/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCRYPTO = 0;
#endif
/*
 * AES-128 processes data 16 bytes at a time
 */
#define AJ_BLOCKSZ 16

#if AJ_CCM_TRACE
#define Trace(tag, data, len) AJ_DumpBytes(tag, data, len)
#else
#define Trace(tag, data, len)
#endif

/*
 * Struct for a single AES data block
 */
typedef struct _AES_Block {
    uint8_t data[AJ_BLOCKSZ];
} AES_Block;

#define ZERO(b)  memset((b).data, 0, AJ_BLOCKSZ);

/*
 * Struct holding CCM state information
 */
typedef struct _CCM_Context {
    AES_Block T;      /* authentication tag */
    AES_Block ivec0;  /* ivec for CBC MAC */
    AES_Block ivec;   /* ivec for CTR mode encrypt/decrypt */
    union {
        AES_Block A;   /* Working data for CBC MAC */
        AES_Block B_0; /* Initial block for CBC MAC */
    };
} CCM_Context;

/**
 * Compute the CBC MAC over some data
 */
static void CBC_MAC(const uint8_t* key, const uint8_t* in, uint32_t len, CCM_Context* context)
{
    while (len >= AJ_BLOCKSZ) {
        AJ_AES_CBC_128_ENCRYPT(key, in, context->T.data, AJ_BLOCKSZ, context->ivec0.data);
        Trace("After AES", context->T.data, AJ_BLOCKSZ);
        in += AJ_BLOCKSZ;
        len -= AJ_BLOCKSZ;
    }
    if (len) {
        ZERO(context->A);
        memcpy(context->A.data, in, len);
        AJ_AES_CBC_128_ENCRYPT(key, context->A.data, context->T.data, AJ_BLOCKSZ, context->ivec0.data);
        Trace("After AES", context->T.data, AJ_BLOCKSZ);
    }
}

/**
 * Compute the AES-CCM authentication tag.
 */
static void Compute_CCM_AuthTag(const uint8_t* key,
                                CCM_Context* context,
                                const uint8_t* msg,
                                uint32_t mLen,
                                uint32_t hdrLen)
{
    /*
     * Initialize CBC-MAC with B_0 initialization vector is 0.
     */
    Trace("CBC IV in", context->B_0.data, AJ_BLOCKSZ);
    AJ_AES_CBC_128_ENCRYPT(key, context->B_0.data, context->T.data, AJ_BLOCKSZ, context->ivec0.data);
    Trace("CBC IV out", context->T.data, AJ_BLOCKSZ);
    /*
     * Compute CBC-MAC for the add data.
     */
    if (hdrLen) {
        uint32_t firstFew;
        /*
         * This encodes the header data length and the first few bytes of the header data
         */
        ZERO(context->A);
        context->A.data[0] = (uint8_t)(hdrLen >> 8);
        context->A.data[1] = (uint8_t)(hdrLen >> 0);
        firstFew = min(hdrLen, 14);
        memcpy(&context->A.data[2], msg, firstFew);
        /*
         * Adjust for the hdr data bytes that were encoded in the length block
         */
        msg += firstFew;
        hdrLen -= firstFew;
        /*
         * Continue the MAC by encrypting the length block
         */
        Trace("Before AES", context->A.data, AJ_BLOCKSZ);
        AJ_AES_CBC_128_ENCRYPT(key, context->A.data, context->T.data, AJ_BLOCKSZ, context->ivec0.data);
        Trace("After AES", context->T.data, AJ_BLOCKSZ);
        /*
         * Continue computing the CBC-MAC
         */
        CBC_MAC(key, msg, hdrLen, context);
        msg += hdrLen;
    }
    /*
     * Continue computing CBC-MAC over the message data.
     */
    if (mLen) {
        CBC_MAC(key, msg, mLen, context);
    }
    Trace("CBC-MAC", context->T.data, context->M);
}

static CCM_Context* InitCCMContext(const uint8_t* nonce, uint32_t nLen, uint32_t hdrLen, uint32_t msgLen, uint8_t M)
{
    int i;
    int l;
    uint8_t L  = 15 - max(nLen, 11);
    uint8_t flags = ((hdrLen) ? 0x40 : 0) | (((M - 2) / 2) << 3) | (L - 1);
    CCM_Context* context;

    AJ_ASSERT(nLen <= 15);

    context = (CCM_Context*)AJ_Malloc(sizeof(CCM_Context));
    if (context) {
        memset(context, 0, sizeof(CCM_Context));
        /*
         * Set ivec and other initial args.
         */
        context->ivec.data[0] = L - 1;
        memcpy(&context->ivec.data[1], nonce, nLen);
        /*
         * Compute the B_0 block. This encodes the flags, the nonce, and the message length.
         */
        context->B_0.data[0] = flags;
        memcpy(&context->B_0.data[1], nonce, nLen);
        for (i = 15, l = msgLen - hdrLen; l != 0; i--) {
            context->B_0.data[i] = (uint8_t)l;
            l >>= 8;
        }
    }
    return context;
}

/*
 * Implements AES-CCM (Counter with CBC-MAC) encryption as described in RFC 3610
 */
AJ_Status AJ_Encrypt_CCM(const uint8_t* key,
                         uint8_t* msg,
                         uint32_t msgLen,
                         uint32_t hdrLen,
                         uint8_t tagLen,
                         const uint8_t* nonce,
                         uint32_t nLen)
{
    AJ_Status status = AJ_OK;
    CCM_Context* context;

    if (!(context = InitCCMContext(nonce, nLen, hdrLen, msgLen, tagLen))) {
        AJ_ErrPrintf(("AJ_Encrypt_CCM(): AJ_ERR_RESOURCES\n"));
        return AJ_ERR_RESOURCES;
    }
    /*
     * Do any platform specific operations to enable AES
     */
    AJ_AES_Enable(key);
    /*
     * Compute the authentication tag
     */
    Compute_CCM_AuthTag(key, context, msg, msgLen - hdrLen, hdrLen);
    /*
     * Encrypt the authentication tag
     */
    AJ_AES_CTR_128(key, context->T.data, msg + msgLen, tagLen, context->ivec.data);
    Trace("CTR Start", context->ivec.data, AJ_BLOCKSZ);
    /*
     * Encrypt the message
     */
    if (msgLen != hdrLen) {
        AJ_AES_CTR_128(key, msg + hdrLen, msg + hdrLen, msgLen - hdrLen, context->ivec.data);
    }
    /*
     * Balance the enable call above
     */
    AJ_AES_Disable();
    /*
     * Done with the context
     */
    AJ_Free(context);
    return status;
}

/*
 * Implements AES-CCM (Counter with CBC-MAC) decryption as described in RFC 3610
 */
AJ_Status AJ_Decrypt_CCM(const uint8_t* key,
                         uint8_t* msg,
                         uint32_t msgLen,
                         uint32_t hdrLen,
                         uint8_t tagLen,
                         const uint8_t* nonce,
                         uint32_t nLen)
{
    AJ_Status status = AJ_OK;
    CCM_Context* context;

    if (!(context = InitCCMContext(nonce, nLen, hdrLen, msgLen, tagLen))) {
        AJ_ErrPrintf(("AJ_Decrypt_CCM(): AJ_ERR_RESOURCES\n"));
        return AJ_ERR_RESOURCES;
    }
    /*
     * Do any platform specific operations to enable AES
     */
    AJ_AES_Enable(key);
    /*
     * Decrypt the authentication field
     */
    AJ_AES_CTR_128(key, msg + msgLen, msg + msgLen, tagLen, context->ivec.data);
    /*
     * Decrypt message.
     */
    if (msgLen != hdrLen) {
        AJ_AES_CTR_128(key, msg + hdrLen, msg + hdrLen, msgLen - hdrLen, context->ivec.data);
    }
    /*
     * Compute and verify the authentication tag T.
     */
    Compute_CCM_AuthTag(key, context, msg, msgLen - hdrLen, hdrLen);
    /*
     * Balance the enable call above
     */
    AJ_AES_Disable();
    if (AJ_Crypto_Compare(context->T.data, msg + msgLen, tagLen) != 0) {
        /*
         * Authentication failed Clear the decrypted data
         */
        memset(msg, 0, msgLen + tagLen);
        AJ_ErrPrintf(("AJ_Decrypt_CCM(): AJ_ERR_SECURITY\n"));
        status = AJ_ERR_SECURITY;
    }
    /*
     * Done with the context
     */
    AJ_Free(context);
    return status;
}
