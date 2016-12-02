#ifndef _AJ_CRYPTO_AES_PRIV_H
#define _AJ_CRYPTO_AES_PRIV_H

/**
 * @file aj_crypto_aes_priv.h
 * @defgroup Private functions for low-level AES implementation
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
 * AES counter mode encryption/decryption. Note that in CTR mode encrytion is its own inverse.
 *
 * @param key  The AES encryption key
 * @param in   The data to encrypt
 * @param out  The encrypted data
 * @param len  The length of the input data, must be multiple of 16
 * @param ctr  Pointer to a 16 byte counter block
 */
void AJ_AES_CTR_128(const uint8_t* key, const uint8_t* in, uint8_t* out, uint32_t len, uint8_t* ctr);

/**
 * AES CCM mode encryption
 *
 * @param key  The AES encryption key
 * @param in   The data to encrypt
 * @param out  The encrypted data
 * @param len  The length of the input data, must be multiple of 16
 * @param iv   Pointer to a 16 byte initialization vector
 */
void AJ_AES_CBC_128_ENCRYPT(const uint8_t* key, const uint8_t* in, uint8_t* out, uint32_t len, uint8_t* iv);


/**
 * Encrypt a single 16 byte block using AES in ECB mode
 *
 * @param key  The AES encryption key
 * @param in   The data to encrypt
 * @param out  The encrypted data
 */
void AJ_AES_ECB_128_ENCRYPT(const uint8_t* key, const uint8_t* in, uint8_t* out);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif