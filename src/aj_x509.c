/**
 * @file aj_x509.c
 *
 * Utilites for X.509 Certificates
 */
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE X509

#include "aj_debug.h"
#include "aj_creds.h"
#include "aj_util.h"
#include "aj_x509.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgX509 = 0;
#endif

// 1.2.840.10045.4.3.2
const uint8_t OID_SIG_ECDSA_SHA256[]  = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
// 1.2.840.10045.2.1
const uint8_t OID_KEY_ECC[]           = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
// 1.2.840.10045.3.1.7
const uint8_t OID_CRV_PRIME256V1[]    = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
// 2.5.4.10
const uint8_t OID_DN_OU[]             = { 0x55, 0x04, 0x0B };
// 2.5.4.3
const uint8_t OID_DN_CN[]             = { 0x55, 0x04, 0x03 };
// 2.5.29.19
const uint8_t OID_BASIC_CONSTRAINTS[] = { 0x55, 0x1D, 0x13 };

uint8_t CompareOID(DER_Element* der, const uint8_t* oid, size_t len)
{
    if (der->size != len) {
        return 0;
    }
    return (0 == memcmp(der->data, oid, len));
}

static AJ_Status DecodeCertificateName(DER_Element* der, uint8_t type, AJ_GUID* ou, AJ_GUID* cn)
{
    AJ_Status status = AJ_OK;
    DER_Element set;
    DER_Element seq;
    DER_Element oid;
    DER_Element tmp;

    while ((AJ_OK == status) && (der->size)) {
        status = AJ_ASN1DecodeElement(der, ASN_SET_OF, &set);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_ASN1DecodeElement(&set, ASN_SEQ, &seq);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_ASN1DecodeElement(&seq, ASN_OID, &oid);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_ASN1DecodeElement(&seq, ASN_UTF8, &tmp);
        if (AJ_OK != status) {
            return status;
        }
        if (CompareOID(&oid, OID_DN_OU, sizeof (OID_DN_OU))) {
            status = AJ_GUID_FromString(ou, (const char*) tmp.data);
            if (AJ_OK != status) {
                return status;
            }
        } else if (CompareOID(&oid, OID_DN_CN, sizeof (OID_DN_CN))) {
            status = AJ_GUID_FromString(cn, (const char*) tmp.data);
            if (AJ_OK != status) {
                return status;
            }
        }
    }

    return status;
}

static AJ_Status DecodeCertificatePub(DER_Element* der, ecc_publickey* publickey)
{
    AJ_Status status;
    DER_Element seq;
    DER_Element bit;
    DER_Element oid1;
    DER_Element oid2;
    uint8_t tags1[] = { ASN_SEQ, ASN_BITS };
    uint8_t tags2[] = { ASN_OID, ASN_OID };

    status = AJ_ASN1DecodeElements(der, tags1, sizeof (tags1), &seq, &bit);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * We only accept NISTP256 ECC keys at the moment.
     */
    status = AJ_ASN1DecodeElements(&seq, tags2, sizeof (tags2), &oid1, &oid2);
    if (AJ_OK != status) {
        return status;
    }
    if (sizeof (OID_KEY_ECC) != oid1.size) {
        return AJ_ERR_INVALID;
    }
    if (0 != memcmp(OID_KEY_ECC, oid1.data, oid1.size)) {
        return AJ_ERR_INVALID;
    }
    if (sizeof (OID_CRV_PRIME256V1) != oid2.size) {
        return AJ_ERR_INVALID;
    }
    if (0 != memcmp(OID_CRV_PRIME256V1, oid2.data, oid2.size)) {
        return AJ_ERR_INVALID;
    }

    /*
     * We only accept uncompressed ECC points.
     */
    if ((2 + KEY_ECC_PUB_SZ) != bit.size) {
        return AJ_ERR_INVALID;
    }
    if ((0x00 != bit.data[0]) || (0x04 != bit.data[1])) {
        return AJ_ERR_INVALID;
    }
    bit.data += 2;
    bit.size -= 2;

    memset(publickey, 0, sizeof (ecc_publickey));
    AJ_BigvalDecode(bit.data, &publickey->x, KEY_ECC_SZ);
    bit.data += KEY_ECC_SZ;
    bit.size -= KEY_ECC_SZ;
    AJ_BigvalDecode(bit.data, &publickey->y, KEY_ECC_SZ);

    return status;
}

static AJ_Status DecodeCertificateExt(DER_Element* der)
{
    AJ_Status status;
    DER_Element tmp;
    DER_Element seq;
    DER_Element oid;
    DER_Element oct;
    uint8_t tags[] = { ASN_OID, ASN_OCTETS };

    status = AJ_ASN1DecodeElement(der, ASN_SEQ, &tmp);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_ASN1DecodeElement(&tmp, ASN_SEQ, &seq);
    if (AJ_OK != status) {
        return status;
    }

    status = AJ_ASN1DecodeElements(&seq, tags, sizeof (tags), &oid, &oct);
    if (AJ_OK != status) {
        return status;
    }
    if (sizeof (OID_BASIC_CONSTRAINTS) != oid.size) {
        return AJ_ERR_INVALID;
    }
    if (0 != memcmp(OID_BASIC_CONSTRAINTS, oid.data, oid.size)) {
        return AJ_ERR_INVALID;
    }

    status = AJ_ASN1DecodeElement(&oct, ASN_SEQ, &seq);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_ASN1DecodeElement(&seq, ASN_BOOLEAN, &tmp);

    return status;
}

static AJ_Status DecodeCertificateTBS(X509Certificate* certificate, DER_Element* tbs)
{
    AJ_Status status;
    DER_Element ver;
    DER_Element oid;
    DER_Element iss;
    DER_Element utc;
    DER_Element sub;
    DER_Element pub;
    DER_Element ext;
    DER_Element tmp;
    DER_Element time1;
    DER_Element time2;
    uint8_t tags1[] = { ASN_CONTEXT_SPECIFIC, ASN_INTEGER, ASN_SEQ, ASN_SEQ, ASN_SEQ, ASN_SEQ, ASN_SEQ, ASN_CONTEXT_SPECIFIC };
    uint8_t tags2[] = { ASN_UTC_TIME, ASN_UTC_TIME };

    status = AJ_ASN1DecodeElements(tbs, tags1, sizeof (tags1), 0, &ver, &certificate->serial, &oid, &iss, &utc, &sub, &pub, 3, &ext);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * We only accept X.509v3 certificates.
     */
    status = AJ_ASN1DecodeElement(&ver, ASN_INTEGER, &tmp);
    if (AJ_OK != status) {
        return status;
    }
    if ((0x1 != tmp.size) || (0x2 != *tmp.data)) {
        return AJ_ERR_INVALID;
    }

    /*
     * We only accept ECDSA-SHA256 signed certificates at the moment.
     */
    status = AJ_ASN1DecodeElement(&oid, ASN_OID, &tmp);
    if (AJ_OK != status) {
        return status;
    }
    if (sizeof (OID_SIG_ECDSA_SHA256) != tmp.size) {
        return AJ_ERR_INVALID;
    }
    if (0 != memcmp(OID_SIG_ECDSA_SHA256, tmp.data, tmp.size)) {
        return AJ_ERR_INVALID;
    }

    status = DecodeCertificateName(&iss, 0, NULL, &certificate->issuer);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_ASN1DecodeElements(&utc, tags2, sizeof (tags2), &time1, &time2);
    if (AJ_OK != status) {
        return status;
    }
    status = DecodeCertificateName(&sub, 0, &certificate->guild, &certificate->subject);
    if (AJ_OK != status) {
        return status;
    }
    status = DecodeCertificatePub(&pub, &certificate->publickey);
    if (AJ_OK != status) {
        return status;
    }
    status = DecodeCertificateExt(&ext);

    return status;
}

static AJ_Status DecodeCertificateSig(DER_Element* der, ecc_signature* signature)
{
    AJ_Status status;
    DER_Element seq;
    DER_Element int1;
    DER_Element int2;
    uint8_t tags[] = { ASN_INTEGER, ASN_INTEGER };

    status = AJ_ASN1DecodeElement(der, ASN_SEQ, &seq);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_ASN1DecodeElements(&seq, tags, sizeof (tags), &int1, &int2);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * Skip over unused bits.
     */
    if ((0 < int1.size) && (0 == *int1.data)) {
        int1.data++;
        int1.size--;
    }
    if ((0 < int2.size) && (0 == *int2.data)) {
        int2.data++;
        int2.size--;
    }

    memset(signature, 0, sizeof (ecc_signature));
    AJ_BigvalDecode(int1.data, &signature->r, int1.size);
    AJ_BigvalDecode(int2.data, &signature->s, int2.size);

    return status;
}

AJ_Status AJ_X509DecodeCertificateDER(X509Certificate* certificate, DER_Element* der)
{
    AJ_Status status;
    DER_Element seq;
    DER_Element tbs;
    DER_Element tmp;
    DER_Element oid;
    DER_Element sig;
    uint8_t tags1[] = { ASN_SEQ };
    uint8_t tags2[] = { ASN_SEQ, ASN_SEQ, ASN_BITS };

    AJ_InfoPrintf(("AJ_X509DecodeCertificateDER(certificate=%p, der=%p)\n", certificate, der));

    if ((NULL == certificate) || (NULL == der)) {
        return AJ_ERR_INVALID;
    }

    status = AJ_ASN1DecodeElements(der, tags1, sizeof (tags1), &seq);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_ASN1DecodeElements(&seq, tags2, sizeof (tags2), &tbs, &tmp, &sig);
    if (AJ_OK != status) {
        return status;
    }
    /*
     * The signed TBS includes the sequence and length fields.
     */
    certificate->tbs.data = tbs.data - 4;
    certificate->tbs.size = tbs.size + 4;

    status = DecodeCertificateTBS(certificate, &tbs);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * We only accept ECDSA-SHA256 signed certificates at the moment.
     */
    status = AJ_ASN1DecodeElement(&tmp, ASN_OID, &oid);
    if (AJ_OK != status) {
        return status;
    }
    if (sizeof (OID_SIG_ECDSA_SHA256) != oid.size) {
        return AJ_ERR_INVALID;
    }
    if (0 != memcmp(OID_SIG_ECDSA_SHA256, oid.data, oid.size)) {
        return AJ_ERR_INVALID;
    }

    /*
     * Remove the byte specifying unused bits, this should always be zero.
     */
    if ((0 == sig.size) || (0 != *sig.data)) {
        return AJ_ERR_INVALID;
    }
    sig.data++;
    sig.size--;
    status = DecodeCertificateSig(&sig, &certificate->signature);

    return status;
}

AJ_Status AJ_X509SelfVerify(const X509Certificate* certificate)
{
    AJ_InfoPrintf(("AJ_X509SelfVerify(certificate=%p)\n", certificate));
    return AJ_ECDSAVerify(certificate->tbs.data, certificate->tbs.size, &certificate->signature, &certificate->publickey);
}

AJ_Status AJ_X509Verify(const X509Certificate* certificate, const AJ_KeyInfo* key)
{
    AJ_InfoPrintf(("AJ_X509Verify(certificate=%p, key=%p)\n", certificate, key));
    return AJ_ECDSAVerify(certificate->tbs.data, certificate->tbs.size, &certificate->signature, &key->key.publickey);
}
