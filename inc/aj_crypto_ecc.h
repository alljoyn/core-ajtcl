#ifndef _AJ_CRYPTO_ECC_H
#define _AJ_CRYPTO_ECC_H

/**
 * @file aj_crypto_ecc.h
 * @defgroup aj_crypto Cryptographic Support
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
#include <ajtcl/aj_guid.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {B_FALSE, B_TRUE} boolean_t;

/**
 * ECC type sizes
 */
#define KEY_ECC_SZ (8 * sizeof (uint32_t))
#define KEY_ECC_PRV_SZ KEY_ECC_SZ
#define KEY_ECC_PUB_SZ (2 * KEY_ECC_SZ)
#define KEY_ECC_SIG_SZ (2 * KEY_ECC_SZ)

/* Size of affine_point_t */
#define KEY_ECC_OLD_SZ (19 * sizeof (uint32_t))

/**
 * Key and curve types for AJ_ECC key types
 */
#define KEY_ALG_ECDSA_SHA256 0
#define KEY_ALG_ECSPEKE      1
#define KEY_CRV_NISTP256     0
typedef struct _AJ_ECCPublicKey {
    uint8_t alg;                   /**< Algorithm */
    uint8_t crv;                   /**< Elliptic curve */
    uint8_t x[KEY_ECC_SZ];
    uint8_t y[KEY_ECC_SZ];
} AJ_ECCPublicKey;

typedef struct _AJ_ECCPrivateKey {
    uint8_t alg;                   /**< Algorithm */
    uint8_t crv;                   /**< Elliptic curve */
    uint8_t x[KEY_ECC_SZ];
} AJ_ECCPrivateKey;

typedef AJ_ECCPrivateKey AJ_ECCSecret;

typedef struct _AJ_ECCSignature {
    uint8_t alg;                   /**< Algorithm */
    uint8_t crv;                   /**< Elliptic curve */
    uint8_t r[KEY_ECC_SZ];
    uint8_t s[KEY_ECC_SZ];
} AJ_ECCSignature;

/**
 * Generates an ECC key pair.
 *
 * @param pub The output public key
 * @param prv The output private key
 *
 * @return  - AJ_OK if the key pair is successfully generated.
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_GenerateECCKeyPair(AJ_ECCPublicKey* pub, AJ_ECCPrivateKey* prv);

/**
 * Generates the Diffie-Hellman share secret.
 *
 * @param pub The peer's public key
 * @param prv The private key
 * @param sec The output share secret
 *
 * @return  - AJ_OK if the share secret is successfully generated.
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_GenerateShareSecret(AJ_ECCPublicKey* pub, AJ_ECCPrivateKey* prv, AJ_ECCSecret* sec);

/**
 * Sign a digest using the DSA key
 * @param digest The digest to sign
 * @param prv The signing private key
 * @param sig The output signature
 * @return  - AJ_OK if the signing process succeeds
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_ECDSASignDigest(const uint8_t* digest, const AJ_ECCPrivateKey* prv, AJ_ECCSignature* sig);

/**
 * Sign a buffer using the DSA key
 * @param buf The buffer to sign
 * @param len The buffer len
 * @param prv The signing private key
 * @param sig The output signature
 * @return  - AJ_OK if the signing process succeeds
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_ECDSASign(const uint8_t* buf, uint16_t len, const AJ_ECCPrivateKey* prv, AJ_ECCSignature* sig);

/**
 * Verify DSA signature of a digest
 * @param digest The digest to sign
 * @param sig The signature
 * @param pub The signing public key
 * @return  - AJ_OK if the signature verification succeeds
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_ECDSAVerifyDigest(const uint8_t* digest, const AJ_ECCSignature* sig, const AJ_ECCPublicKey* pub);

/**
 * Verify DSA signature of a buffer
 * @param buf The buffer to sign
 * @param len The buffer len
 * @param sig The signature
 * @param pub The signing public key
 * @return  - AJ_OK if the signature verification succeeds
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_ECDSAVerify(const uint8_t* buf, uint16_t len, const AJ_ECCSignature* sig, const AJ_ECCPublicKey* pub);

/**
 * Old encoding of native public key.
 *
 * @param pub          The ECC public key
 * @param[out] b8      Big endian byte array
 *
 */
void AJ_BigEndianDecodePublicKey(AJ_ECCPublicKey* pu, uint8_t* b8);

/**
 * Old decoding of native public key.
 *
 * @param[out] pub     The ECC public key
 * @param b8           Big endian byte array
 *
 */
void AJ_BigEndianEncodePublicKey(AJ_ECCPublicKey* pub, uint8_t* b8);

/**
 * Generates the Diffie-Hellman share secret using old encoding.
 *
 * @param pub The peer's public key
 * @param prv The private key
 * @param sec The output share secret
 *
 * @return  - AJ_OK if the share secret is successfully generated.
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_GenerateShareSecretOld(AJ_ECCPublicKey* pub, AJ_ECCPrivateKey* prv, AJ_ECCPublicKey* sec);

/**
 * Generates an ephemeral key pair for EC-SPEKE.
 *
 * @param[in]  pw          Password and additional data to use during key generation
 * @param[in]  pwLen       The byte length of pw
 * @param[in]  clientGUID  The client's GUID
 * @param[in]  serviceGUID The service's GUID
 * @param[out] publicKey   The output public key
 * @param[out] privateKey  The output private key
 *
 * @return  - AJ_OK if the key pair is successfully generated.
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_GenerateSPEKEKeyPair(const uint8_t* pw, size_t pwLen, const AJ_GUID* clientGUID, const AJ_GUID* serviceGUID,
                                  AJ_ECCPublicKey* publicKey, AJ_ECCPrivateKey* privateKey);


#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
