#ifndef _AJ_CRYPTO_DRBG_H
#define _AJ_CRYPTO_DRBG_H

/**
 * @file aj_crypto_drbg.h
 * @defgroup aj_crypto Cryptographic Random Number Generator
 * @{
 */
/******************************************************************************
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * AES-128 CTR DRBG constants
 */
#define OUTLEN 16
#define KEYLEN 16
#define SEEDLEN OUTLEN + KEYLEN

/**
 * Context for AES-128 CTR DRBG
 */
typedef struct _CTR_DRBG_CTX {
    uint8_t df;        /**< Use DF or not */
    uint8_t v[OUTLEN]; /**< Internal working state */
    uint8_t k[KEYLEN]; /**< Key working state */
    uint32_t c;        /**< Reseed counter */
} CTR_DRBG_CTX;

/**
 * AES-128 CTR DRBG instantiate function
 * This takes a seed value: entropy || nonce || personalization
 *
 * @param ctx          The context
 * @param seed         Input seed material
 * @param size         Input seed material size
 * @param df           Use DF or not
 */
void AES_CTR_DRBG_Instantiate(CTR_DRBG_CTX* ctx, uint8_t* seed, size_t size, uint8_t df);

/**
 * AES-128 CTR DRBG reseed function
 * This takes a seed value: entropy || additional
 *
 * @param ctx          The context
 * @param seed         Input seed material
 * @param size         Input seed material size
 */
void AES_CTR_DRBG_Reseed(CTR_DRBG_CTX* ctx, uint8_t* seed, size_t size);

/**
 * AES-128 CTR DRBG generate function
 * This implementation does not take additional input
 *
 * @param ctx          The context
 * @param rand         Output rand material
 * @param size         Required output rand material size
 *
 * @return             Return AJ_Status
 *                     - AJ_OK on success
 *                     - AJ_ERR_SECURITY if reseed required
 */
AJ_Status AES_CTR_DRBG_Generate(CTR_DRBG_CTX* ctx, uint8_t* rand, size_t size);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif