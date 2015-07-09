#ifndef _AJ_CERT_H
#define _AJ_CERT_H

/**
 * @file aj_cert.h
 * @defgroup aj_cert Certificate Utilities
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

#include "aj_target.h"
#include "aj_status.h"
#include "aj_crypto_ecc.h"
#include "aj_creds.h"
#include "aj_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const uint8_t OID_SIG_ECDSA_SHA256[8];
extern const uint8_t OID_KEY_ECC[7];
extern const uint8_t OID_CRV_PRIME256V1[8];
extern const uint8_t OID_DN_OU[3];
extern const uint8_t OID_DN_CN[3];
extern const uint8_t OID_BASIC_CONSTRAINTS[3];
extern const uint8_t OID_SKI[3];
extern const uint8_t OID_AKI[3];
extern const uint8_t OID_SUB_ALTNAME[3];
extern const uint8_t OID_HASH_SHA256[9];
extern const uint8_t OID_CUSTOM_TYPE[10];
extern const uint8_t OID_CUSTOM_DIGEST[10];
extern const uint8_t OID_CUSTOM_GROUP[10];
extern const uint8_t OID_CUSTOM_ALIAS[10];

/**
 * Structure for a DER encoded element.
 */
typedef struct _DER_Element {
    size_t size;
    uint8_t* data;
} DER_Element;

/**
 * Decode one element from a DER encoded blob.
 *
 * @param der The input DER encoded blob.
 * @param tag The expected element type.
 * @param out The output decoded element.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_ASN1DecodeElement(DER_Element* der, uint8_t tag, DER_Element* out);

/**
 * Decode many elements from a DER encoded blob.
 * This is a non-recursive decoder.
 * Only a depth of one may be decoded in one call.
 *
 * @param der  The input DER encoded blob.
 * @param tags The expected element types.
 * @param len  The number of types to decode.
 * @param ...  The output decoded elements.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_ASN1DecodeElements(DER_Element* der, const uint8_t* tags, size_t len, ...);

#define CERT_FMT_X509_DER  0

typedef struct _X509Validity {
    uint64_t from;
    uint64_t to;
} X509Validity;

typedef struct _X509DistinguishedName {
    DER_Element ou;                      /**< Organizational Unit name */
    DER_Element cn;                      /**< Common name */
} X509DistinguishedName;

typedef struct _X509Extensions {
    uint32_t ca;                         /**< Certificate authority */
    uint32_t type;                       /**< Certificate type in AllJoyn ecosystem */
    DER_Element ski;                     /**< Subject Key Identifier */
    DER_Element aki;                     /**< Authority Key Identifier */
    DER_Element alias;                   /**< Alias (subject alt name) */
    DER_Element group;                   /**< Group (subject alt name) */
    DER_Element digest;                  /**< Associated digest */
} X509Extensions;

typedef struct _X509TbsCertificate {
    DER_Element serial;                  /**< The serial number */
    X509DistinguishedName issuer;        /**< The issuer's identity */
    X509Validity validity;               /**< The validity period */
    X509DistinguishedName subject;       /**< The subject's identity */
    AJ_ECCPublicKey publickey;           /**< The subject's public key */
    X509Extensions extensions;           /**< The certificate extensions */
} X509TbsCertificate;

/**
 * Structure for X.509 certificate.
 * Only useful for NISTP256 ECDSA signed certificates at the moment.
 * Can be modified to handle other types in the future.
 */
typedef struct _X509Certificate {
    DER_Element der;                     /**< Certificate DER encoding */
    DER_Element raw;                     /**< The raw tbs section */
    X509TbsCertificate tbs;              /**< The TBS section of the certificate */
    AJ_ECCSignature signature;           /**< The certificate signature */
} X509Certificate;

/**
 * Certificate chain: linked list of certificates
 */
typedef struct _X509CertificateChain {
    X509Certificate certificate;         /**< The certificate */
    struct _X509CertificateChain* next;  /**< Linked list pointer */
} X509CertificateChain;

/**
 * Decode a PEM encoded private key
 *
 * @param key         The output decoded key.
 * @param pem         The input PEM.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_DecodePrivateKeyPEM(AJ_ECCPrivateKey* key, const char* pem);

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
 * Decode a PEM encoded X.509 certificate.
 *
 * @param certificate The output decoded certificate.
 * @param pem         The input PEM.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_RESOURCES on failure
 */
AJ_Status AJ_X509DecodeCertificatePEM(X509Certificate* certificate, const char* pem);

/**
 * Decode a PEM encoded X.509 certificate chain.
 * The order of certificates is important.
 * This puts the child first, then parents follow.
 * That is the same order that should be in the pem.
 *
 * @param pem         The input PEM.
 *
 * @return  Return chain on success, NULL on failure
 */
X509CertificateChain* AJ_X509DecodeCertificateChainPEM(const char* pem);

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
AJ_Status AJ_X509Verify(const X509Certificate* certificate, const AJ_ECCPublicKey* key);

/**
 * Verify a chain of X.509 certificates.
 * Root certificate is first.
 *
 * @param chain       The input certificate chain.
 * @param key         The verification key of the root. If this is NULL, don't verify the root.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_X509VerifyChain(const X509CertificateChain* chain, const AJ_ECCPublicKey* key);

/**
 * Free memory associated with X.509 chain.
 *
 * @param head        The input certificate chain.
 */
void AJ_X509ChainFree(X509CertificateChain* head);

/**
 * Marshal a X.509 certificate chain.
 *
 * @param chain       The input certificate chain.
 * @param msg         The message.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_X509ChainMarshal(X509CertificateChain* chain, AJ_Message* msg);

/**
 * Unmarshal a X.509 certificate chain.
 *
 * @param chain       The output certificate chain.
 * @param msg         The message.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_X509ChainUnmarshal(X509CertificateChain** chain, AJ_Message* msg);

/**
 * Marshal a X.509 certificate chain to a local buffer.
 *
 * @param chain       The input certificate chain.
 * @param field       The local buffer.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_X509ChainToBuffer(X509CertificateChain* chain, AJ_CredField* field);

/**
 * Unmarshal a X.509 certificate chain from a local buffer.
 *
 * @param chain       The output certificate chain.
 * @param field       The local buffer.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_X509ChainFromBuffer(X509CertificateChain** chain, AJ_CredField* field);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
