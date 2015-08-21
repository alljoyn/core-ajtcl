#ifndef _AJ_CRYPTO_SHA2_H
#define _AJ_CRYPTO_SHA2_H

/**
 * @file aj_crypto_sha2.h
 * @defgroup aj_crypto SHA-256 Cryptographic Support
 * @{
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

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_status.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AJ_SHA256_DIGEST_LENGTH (32)

typedef struct AJ_SHA256_Context AJ_SHA256_Context;

/*** SHA-256/384/512 Function Prototypes ******************************/

/**
 * Initialize the hash context.  Calls to this function must be
 * matched with a call to AJ_SHA256_Final() to ensure that resources
 * are released.
 *
 * @return Pointer to context. NULL if init failed.
 */
AJ_SHA256_Context* AJ_SHA256_Init(void);

/**
 * Update the digest using the specific bytes
 * @param context the hash context
 * @param buf the bytes to digest
 * @param bufSize the number of bytes to digest
 */
void AJ_SHA256_Update(AJ_SHA256_Context* context, const uint8_t* buf, size_t bufSize);

/**
 * Retrieve the digest but keep the hash active for further updates.
 * @param context the hash context
 * @param digest the buffer to hold the digest.  Must be of size AJ_SHA256_DIGEST_LENGTH
 * @return AJ_OK if successful, otherwise error.
 */
AJ_Status AJ_SHA256_GetDigest(AJ_SHA256_Context* context, uint8_t* digest);

/**
 * Finish the hash calculation and free resources.
 * @param context the hash context
 * @param digest - the buffer to hold the digest.
 *        Must be NULL or of size AJ_SHA256_DIGEST_LENGTH.
 *        If the value is NULL, resources are freed but the digest
 *        is not calculated.
 * @return AJ_OK if successful, otherwise error.
 */
AJ_Status AJ_SHA256_Final(AJ_SHA256_Context* context, uint8_t* digest);

/**
 * Random function
 * @param inputs    array holding secret, label, seed
 * @param lengths   array holding the lengths of the inputs
 * @param count     the size of the input array
 * @param out       the buffer holding the random value
 * @param outLen    the buffer size
 * @return AJ_OK if succeeds; otherwise error
 */
AJ_Status AJ_Crypto_PRF_SHA256(const uint8_t** inputs, const uint8_t* lengths,
                               uint32_t count, uint8_t* out, uint32_t outLen);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
