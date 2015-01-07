#ifndef _AJ_X509_H
#define _AJ_X509_H
/**
 * @file
 *
 * Header file for X.509 certificate utilities
 */

/******************************************************************************
 * Copyright (c) 2014-2015, AllSeen Alliance. All rights reserved.
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

#include "aj_asn1.h"
#include "aj_creds.h"
#include "aj_crypto_ecc.h"
#include "aj_guid.h"

/**
 * OIDs used in X.509 certificates.
 */
extern const uint8_t OID_SIG_ECDSA_SHA256[];
extern const uint8_t OID_KEY_ECC[];
extern const uint8_t OID_CRV_PRIME256V1[];
extern const uint8_t OID_DN_OU[];
extern const uint8_t OID_DN_CN[];
extern const uint8_t OID_BASIC_CONSTRAINTS[];
extern const uint8_t OID_SUB_ALTNAME[];
extern const uint8_t OID_DIG_SHA256[];
extern const uint8_t OID_CUSTOM_DIGEST[];
extern const uint8_t OID_CUSTOM_CERT_TYPE[];

typedef enum {
    UNKNOWN_CERTIFICATE,
    IDENTITY_CERTIFICATE,
    MEMBERSHIP_CERTIFICATE
} CertificateType;

/**
 * Structure for X.509 certificate.
 * Only useful for NISTP256 ECDSA signed certificates at the moment.
 * Can be modified to handle other types in the future.
 */
typedef struct _X509Certificate {
    CertificateType type;                 /**< The certificate type */
    DER_Element tbs;                      /**< The TBS section of the certificate */
    DER_Element serial;                   /**< The serial number */
    AJ_GUID issuer;                       /**< The issuer's identity */
    AJ_GUID subject;                      /**< The subject's identity */
    AJ_GUID guild;                        /**< The subject's guild membership */
    AJ_KeyInfo keyinfo;                   /**< The subject's public key */
    DER_Element alias;                    /**< The subject's alias */
    uint8_t digest[SHA256_DIGEST_LENGTH]; /**< Digest field */
    ecc_signature signature;              /**< The certificate signature */
} X509Certificate;

/**
 * Decode a ASN.1 DER encoded X.509 certificate.
 *
 * @param certificate The output decoded certificate.
 * @param der         The input encoded DER blob.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_X509DecodeCertificateDER(X509Certificate* certificate, DER_Element* der);

/**
 * Verify a self-signed X.509 certificate.
 *
 * @param certificate The input certificate.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_X509SelfVerify(const X509Certificate* certificate);

/**
 * Verify a signed X.509 certificate.
 *
 * @param certificate The input certificate.
 * @param key         The verification key.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_X509Verify(const X509Certificate* certificate, const AJ_KeyInfo* key);

#endif
