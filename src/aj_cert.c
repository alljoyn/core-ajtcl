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
#define AJ_MODULE CERTIFICATE

#include <stdarg.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_util.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCERTIFICATE = 0;
#endif

/**
 * DER encoding types.
 */
#define ASN_BOOLEAN          0x01
#define ASN_INTEGER          0x02
#define ASN_BITS             0x03
#define ASN_OCTETS           0x04
#define ASN_NULL             0x05
#define ASN_OID              0x06
#define ASN_UTF8             0x0C
#define ASN_SEQ              0x10
#define ASN_SET_OF           0x11
#define ASN_PRINTABLE        0x13
#define ASN_ASCII            0x16
#define ASN_UTC_TIME         0x17
#define ASN_GEN_TIME         0x18
#define ASN_CONTEXT_SPECIFIC 0x80
#define ASN_UNKNOWN          0xFF

/**
 * PEM encoding tags
 */
#define PEM_PRIV_BEG "-----BEGIN EC PRIVATE KEY-----"
#define PEM_PRIV_END "-----END EC PRIVATE KEY-----"
#define PEM_CERT_BEG "-----BEGIN CERTIFICATE-----"
#define PEM_CERT_END "-----END CERTIFICATE-----"

static uint8_t ASN1DecodeTag(DER_Element* der)
{
    return der->size ? *der->data : ASN_UNKNOWN;
}

static AJ_Status ASN1DecodeLength(DER_Element* der, DER_Element* out)
{
    size_t n;
    size_t len;

    if ((NULL == der->data) || (0 == der->size)) {
        return AJ_ERR_INVALID;
    }

    len = *(der->data)++;
    der->size--;
    if (0x80 & len) {
        n = len & 0x7F;
        if (n > sizeof (size_t)) {
            return AJ_ERR_INVALID;
        }
        len = 0;
        while (n && der->size) {
            len = (len << 8) + *(der->data)++;
            n--;
            der->size--;
        }
    }
    if (len > der->size) {
        return AJ_ERR_INVALID;
    }
    out->size = len;
    out->data = der->data;

    return AJ_OK;
}

/*
 * Currently, only UTF8String is supported in AJ certificates, so binary equivalence
 * is sufficient. If other ASN.1 string types are ever supported, make sure
 * DNs are stored internally in a canonical form that can still be checked for
 * binary equivalence, or this function will need to be updated to do the right things.
   . See RFC 5280 section 7.1 and RFC 4518 for equivalence between different string types.
 */
static uint32_t AJ_X509CompareNames(const X509DistinguishedName a, const X509DistinguishedName b)
{
    /* Only OU and CN are supported as elements in a DN in AllJoyn */
    if (a.ou.size != b.ou.size ||
        a.cn.size != b.cn.size) {
        return FALSE;
    }

    if (0 != memcmp(a.ou.data, b.ou.data, a.ou.size) ||
        0 != memcmp(a.cn.data, b.cn.data, a.cn.size)) {
        return FALSE;
    }

    return TRUE;

}

AJ_Status AJ_ASN1DecodeElement(DER_Element* der, uint8_t tag, DER_Element* out)
{
    uint8_t tmp;

    if ((NULL == der) || (NULL == out)) {
        return AJ_ERR_INVALID;
    }
    if ((NULL == der->data) || (0 == der->size)) {
        return AJ_ERR_INVALID;
    }

    /*
     * Decode tag and check it is what we expect
     */
    tmp = ASN1DecodeTag(der);
    der->data++;
    der->size--;
    /* Turn off primitive/constructed flag */
    tmp &= 0xDF;
    if (tmp != tag) {
        AJ_InfoPrintf(("AJ_ASN1DecodeElement(der=%p, tag=%x, out=%p): Tag error %x\n", der, tag, out, tmp));
        return AJ_ERR_INVALID;
    }
    /*
     * Decode size
     */
    if (AJ_OK != ASN1DecodeLength(der, out)) {
        AJ_InfoPrintf(("AJ_ASN1DecodeElement(der=%p, tag=%x, out=%p): Length error\n", der, tag, out));
        return AJ_ERR_INVALID;
    }
    der->data += out->size;
    der->size -= out->size;

    return AJ_OK;
}

AJ_Status AJ_ASN1DecodeElements(DER_Element* der, const uint8_t* tags, size_t len, ...)
{
    AJ_Status status = AJ_OK;
    DER_Element* out;
    va_list argp;
    uint8_t tag;
    uint32_t tmp;

    AJ_InfoPrintf(("AJ_ASN1DecodeElements(der=%p, tags=%p, len=%zu)\n", der, tags, len));

    if ((NULL == der) || (NULL == tags)) {
        return AJ_ERR_INVALID;
    }

    va_start(argp, len);
    while ((AJ_OK == status) && len && (der->size)) {
        tag = *tags++;
        if (ASN_CONTEXT_SPECIFIC == tag) {
            tmp = va_arg(argp, uint32_t);
            tag = (ASN_CONTEXT_SPECIFIC | tmp);
        }
        out = va_arg(argp, DER_Element*);
        len--;
        status = AJ_ASN1DecodeElement(der, tag, out);
    }
    if (AJ_OK == status) {
        // If unset elements, fail
        if (len) {
            AJ_InfoPrintf(("AJ_ASN1DecodeElements(der=%p, tags=%p, len=%zu): Uninitialized elements\n", der, tags, len));
            status = AJ_ERR_INVALID;
        }
    }
    va_end(argp);

    return status;
}

// 1.2.840.10045.4.3.2
const uint8_t OID_SIG_ECDSA_SHA256[8]       = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
// 1.2.840.10045.2.1
const uint8_t OID_KEY_ECC[7]                = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
// 1.2.840.10045.3.1.7
const uint8_t OID_CRV_PRIME256V1[8]         = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
// 2.5.4.10
const uint8_t OID_DN_OU[3]                  = { 0x55, 0x04, 0x0B };
// 2.5.4.3
const uint8_t OID_DN_CN[3]                  = { 0x55, 0x04, 0x03 };
// 2.5.29.19
const uint8_t OID_BASIC_CONSTRAINTS[3]      = { 0x55, 0x1D, 0x13 };
// 2.5.29.14
const uint8_t OID_SKI[3]                    = { 0x55, 0x1D, 0x0E };
// 2.5.29.35
const uint8_t OID_AKI[3]                    = { 0x55, 0x1D, 0x23 };
// 2.5.29.37
const uint8_t OID_EKU[3]                    = { 0x55, 0x1D, 0x25 };
// 2.5.29.27
const uint8_t OID_SUB_ALTNAME[3]            = { 0x55, 0x1D, 0x11 };
// 2.16.840.1.101.3.4.2.1
const uint8_t OID_HASH_SHA256[9]            = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
// 1.3.6.1.4.1.44924.1.1
const uint8_t OID_CUSTOM_EKU_IDENTITY[10]   = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x01 };
// 1.3.6.1.4.1.44924.1.2
const uint8_t OID_CUSTOM_DIGEST[10]         = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x02 };
// 1.3.6.1.4.1.44924.1.3
const uint8_t OID_CUSTOM_GROUP[10]          = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x03 };
// 1.3.6.1.4.1.44924.1.4
const uint8_t OID_CUSTOM_ALIAS[10]          = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x04 };
// 1.3.6.1.4.1.44924.1.5
const uint8_t OID_CUSTOM_EKU_MEMBERSHIP[10] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x05 };

uint8_t CompareOID(DER_Element* der, const uint8_t* oid, size_t len)
{
    if (der->size != len) {
        return 0;
    }
    return (0 == memcmp(der->data, oid, len));
}

AJ_Status AJ_DecodePrivateKeyDER(AJ_ECCPrivateKey* key, DER_Element* der)
{
    AJ_Status status;
    DER_Element seq;
    DER_Element ver;
    DER_Element prv;
    DER_Element alg;
    const uint8_t tags1[] = { ASN_SEQ };
    const uint8_t tags2[] = { ASN_INTEGER, ASN_OCTETS, ASN_CONTEXT_SPECIFIC };

    status = AJ_ASN1DecodeElements(der, tags1, sizeof (tags1), &seq);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_ASN1DecodeElements(&seq, tags2, sizeof (tags2), &ver, &prv, 0, &alg);
    if (AJ_OK != status) {
        return status;
    }
    if ((1 != ver.size) || (1 != *ver.data)) {
        return AJ_ERR_INVALID;
    }
    if (KEY_ECC_PRV_SZ != prv.size) {
        return AJ_ERR_INVALID;
    }
    memcpy(key->x, prv.data, KEY_ECC_SZ);

    return status;
}

AJ_Status AJ_DecodePrivateKeyPEM(AJ_ECCPrivateKey* key, const char* pem)
{
    AJ_Status status;
    const char* beg;
    const char* end;
    DER_Element der;
    uint8_t* buf = NULL;

    beg = strstr(pem, PEM_PRIV_BEG);
    if (NULL == beg) {
        return AJ_ERR_INVALID;
    }
    beg = pem + strlen(PEM_PRIV_BEG);
    end = strstr(beg, PEM_PRIV_END);
    if (NULL == end) {
        return AJ_ERR_INVALID;
    }

    der.size = 3 * (end - beg) / 4;
    der.data = (uint8_t*) AJ_Malloc(der.size);
    if (NULL == der.data) {
        return AJ_ERR_RESOURCES;
    }
    buf = der.data;
    status = AJ_B64ToRaw(beg, end - beg, der.data, der.size);
    if (AJ_OK != status) {
        goto Exit;
    }
    if ('=' == beg[end - beg - 1]) {
        der.size--;
    }
    if ('=' == beg[end - beg - 2]) {
        der.size--;
    }
    status = AJ_DecodePrivateKeyDER(key, &der);

Exit:
    if (buf) {
        AJ_Free(buf);
    }

    return status;
}

static AJ_Status DecodeCertificateName(X509DistinguishedName* dn, DER_Element* der)
{
    AJ_Status status = AJ_OK;
    DER_Element set;
    DER_Element seq;
    DER_Element oid;
    DER_Element tmp;

    memset(dn, 0, sizeof (X509DistinguishedName));

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
        if (CompareOID(&oid, OID_DN_OU, sizeof (OID_DN_OU))) {
            // Only accept UTF8 strings
            status = AJ_ASN1DecodeElement(&seq, ASN_UTF8, &tmp);
            if (AJ_OK != status) {
                return status;
            }
            dn->ou.data = tmp.data;
            dn->ou.size = tmp.size;
        } else if (CompareOID(&oid, OID_DN_CN, sizeof (OID_DN_CN))) {
            // Only accept UTF8 strings
            status = AJ_ASN1DecodeElement(&seq, ASN_UTF8, &tmp);
            if (AJ_OK != status) {
                return status;
            }
            dn->cn.data = tmp.data;
            dn->cn.size = tmp.size;
        }
    }

    return status;
}

static AJ_Status DecodeCertificateTime(X509Validity* validity, DER_Element* der)
{
    AJ_Status status;
    DER_Element time;
    uint8_t fmt;

    memset(validity, 0, sizeof (X509Validity));

    if (!der->size) {
        return AJ_ERR_SECURITY;
    }
    fmt = *der->data;
    switch (fmt) {
    case ASN_UTC_TIME:
        status = AJ_ASN1DecodeElement(der, ASN_UTC_TIME, &time);
        if (AJ_OK != status) {
            return status;
        }
        validity->from = AJ_DecodeTime((char*) time.data, "%y%m%d%H%M%SZ");
        break;

    case ASN_GEN_TIME:
        status = AJ_ASN1DecodeElement(der, ASN_GEN_TIME, &time);
        if (AJ_OK != status) {
            return status;
        }
        validity->from = AJ_DecodeTime((char*) time.data, "%Y%m%d%H%M%SZ");
        break;

    default:
        return AJ_ERR_INVALID;
    }

    if (!der->size) {
        return AJ_ERR_SECURITY;
    }
    fmt = *der->data;
    switch (fmt) {
    case ASN_UTC_TIME:
        status = AJ_ASN1DecodeElement(der, ASN_UTC_TIME, &time);
        if (AJ_OK != status) {
            return status;
        }
        validity->to = AJ_DecodeTime((char*) time.data, "%y%m%d%H%M%SZ");
        break;

    case ASN_GEN_TIME:
        status = AJ_ASN1DecodeElement(der, ASN_GEN_TIME, &time);
        if (AJ_OK != status) {
            return status;
        }
        validity->to = AJ_DecodeTime((char*) time.data, "%Y%m%d%H%M%SZ");
        break;

    default:
        return AJ_ERR_INVALID;
    }

    return status;
}

static AJ_Status DecodeCertificatePub(AJ_ECCPublicKey* pub, DER_Element* der)
{
    AJ_Status status;
    DER_Element seq;
    DER_Element bit;
    DER_Element oid1;
    DER_Element oid2;
    const uint8_t tags1[] = { ASN_SEQ, ASN_BITS };
    const uint8_t tags2[] = { ASN_OID, ASN_OID };

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
    if (!CompareOID(&oid1, OID_KEY_ECC, sizeof (OID_KEY_ECC))) {
        return AJ_ERR_INVALID;
    }
    if (!CompareOID(&oid2, OID_CRV_PRIME256V1, sizeof (OID_CRV_PRIME256V1))) {
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

    pub->alg = KEY_ALG_ECDSA_SHA256;
    pub->crv = KEY_CRV_NISTP256;
    memcpy(pub->x, bit.data, KEY_ECC_SZ);
    memcpy(pub->y, bit.data + KEY_ECC_SZ, KEY_ECC_SZ);

    return status;
}

static AJ_Status DecodeCertificateExt(X509Extensions* extensions, DER_Element* der)
{
    AJ_Status status;
    DER_Element tmp;
    DER_Element seq;
    DER_Element oid;
    DER_Element oct;
    uint8_t tag;
    uint8_t critical;
    const uint8_t tags1[] = { ASN_CONTEXT_SPECIFIC };
    const uint8_t tags2[] = { ASN_OID, ASN_OCTETS };
    const uint8_t tags3[] = { ASN_OID, ASN_CONTEXT_SPECIFIC };

    memset(extensions, 0, sizeof (X509Extensions));

    /* By default, a certificate is unrestricted. Only if we see an EKU extension
     * will this change. */
    extensions->type = AJ_CERTIFICATE_UNR_X509;

    status = AJ_ASN1DecodeElement(der, ASN_SEQ, &tmp);
    if (AJ_OK != status) {
        return status;
    }
    der->size = tmp.size;
    der->data = tmp.data;
    while ((AJ_OK == status) && (der->size)) {
        status = AJ_ASN1DecodeElement(der, ASN_SEQ, &seq);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_ASN1DecodeElement(&seq, ASN_OID, &oid);
        if (AJ_OK != status) {
            return status;
        }
        critical = 0;
        tag = ASN1DecodeTag(&seq);
        if (ASN_BOOLEAN == tag) {
            // Critical extension
            status = AJ_ASN1DecodeElement(&seq, ASN_BOOLEAN, &tmp);
            if (AJ_OK != status) {
                return status;
            }
            if (0x1 == tmp.size) {
                critical = *tmp.data;
            }
        }
        status = AJ_ASN1DecodeElement(&seq, ASN_OCTETS, &oct);
        if (AJ_OK != status) {
            return status;
        }
        if (CompareOID(&oid, OID_BASIC_CONSTRAINTS, sizeof (OID_BASIC_CONSTRAINTS))) {
            status = AJ_ASN1DecodeElement(&oct, ASN_SEQ, &seq);
            if (AJ_OK != status) {
                return status;
            }
            tag = ASN1DecodeTag(&seq);
            if (ASN_BOOLEAN == tag) {
                // Explicit boolean
                status = AJ_ASN1DecodeElement(&seq, ASN_BOOLEAN, &tmp);
                if (AJ_OK != status) {
                    return status;
                }
                if (0x1 == tmp.size) {
                    extensions->ca = *tmp.data;
                }
            }
            tag = ASN1DecodeTag(&seq);
            if (ASN_INTEGER == tag) {
                // Explicit pathlen
                status = AJ_ASN1DecodeElement(&seq, ASN_INTEGER, &tmp);
                if (AJ_OK != status) {
                    return status;
                }
                // We are not using pathlen, so do nothing with it
            }
        } else if (CompareOID(&oid, OID_SKI, sizeof (OID_SKI))) {
            status = AJ_ASN1DecodeElement(&oct, ASN_OCTETS, &tmp);
            if (AJ_OK != status) {
                return status;
            }
            extensions->ski.data = tmp.data;
            extensions->ski.size = tmp.size;
        } else if (CompareOID(&oid, OID_AKI, sizeof (OID_AKI))) {
            status = AJ_ASN1DecodeElement(&oct, ASN_SEQ, &seq);
            if (AJ_OK != status) {
                return status;
            }
            status = AJ_ASN1DecodeElements(&seq, tags1, sizeof (tags1), 0, &tmp);
            if (AJ_OK != status) {
                return status;
            }
            extensions->aki.data = tmp.data;
            extensions->aki.size = tmp.size;
        } else if (CompareOID(&oid, OID_EKU, sizeof (OID_EKU))) {
            status = AJ_ASN1DecodeElement(&oct, ASN_SEQ, &seq);
            if (AJ_OK != status) {
                return status;
            }
            if (seq.size == 0) {
                /* There must be at least one EKU in the sequence. Certificate is invalid if not. */
                return AJ_ERR_INVALID;
            }
            /* We have at least one EKU, so clear out the type previously defaulted to unrestricted. */
            extensions->type = 0;
            while (seq.size > 0) {
                status = AJ_ASN1DecodeElement(&seq, ASN_OID, &tmp);
                if (AJ_OK != status) {
                    return status;
                }

                if (CompareOID(&tmp, OID_CUSTOM_EKU_IDENTITY, sizeof(OID_CUSTOM_EKU_IDENTITY))) {
                    extensions->type |= AJ_CERTIFICATE_IDN_X509;
                } else if (CompareOID(&tmp, OID_CUSTOM_EKU_MEMBERSHIP, sizeof(OID_CUSTOM_EKU_MEMBERSHIP))) {
                    extensions->type |= AJ_CERTIFICATE_MBR_X509;
                }
                /* Skip any unrecognized EKUs. */
            }
            /* If we saw no AllJoyn EKUs, meaning we only saw non-AllJoyn EKUs, set the type as invalid for
             * AllJoyn purposes. */
            if (0 == extensions->type) {
                extensions->type = AJ_CERTIFICATE_INV_X509;
            }
        } else if (CompareOID(&oid, OID_CUSTOM_DIGEST, sizeof (OID_CUSTOM_DIGEST))) {
            status = AJ_ASN1DecodeElement(&oct, ASN_SEQ, &seq);
            if (AJ_OK != status) {
                return status;
            }
            status = AJ_ASN1DecodeElements(&seq, tags2, sizeof (tags2), &oid, &oct);
            if (AJ_OK != status) {
                return status;
            }
            if (!CompareOID(&oid, OID_HASH_SHA256, sizeof (OID_HASH_SHA256))) {
                return AJ_ERR_INVALID;
            }
            extensions->digest.data = oct.data;
            extensions->digest.size = oct.size;
        } else if (CompareOID(&oid, OID_SUB_ALTNAME, sizeof (OID_SUB_ALTNAME))) {
            status = AJ_ASN1DecodeElement(&oct, ASN_SEQ, &seq);
            if (AJ_OK != status) {
                return status;
            }
            status = AJ_ASN1DecodeElements(&seq, tags1, sizeof (tags1), 0, &tmp);
            if (AJ_OK != status) {
                return status;
            }
            status = AJ_ASN1DecodeElements(&tmp, tags3, sizeof (tags3), &oid, 0, &oct);
            if (AJ_OK != status) {
                return status;
            }
            status = AJ_ASN1DecodeElement(&oct, ASN_OCTETS, &tmp);
            if (AJ_OK != status) {
                return status;
            }
            if (CompareOID(&oid, OID_CUSTOM_GROUP, sizeof (OID_CUSTOM_GROUP))) {
                extensions->group.data = tmp.data;
                extensions->group.size = tmp.size;
            } else if (CompareOID(&oid, OID_CUSTOM_ALIAS, sizeof (OID_CUSTOM_ALIAS))) {
                extensions->alias.data = tmp.data;
                extensions->alias.size = tmp.size;
            }
        } else {
            // Unknown OID, if critical return error
            if (critical) {
                return AJ_ERR_INVALID;
            }
        }
    }

    return status;
}

static AJ_Status DecodeCertificateTBS(X509TbsCertificate* tbs, DER_Element* der)
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
    const uint8_t tags[] = { ASN_CONTEXT_SPECIFIC, ASN_INTEGER, ASN_SEQ, ASN_SEQ, ASN_SEQ, ASN_SEQ, ASN_SEQ, ASN_CONTEXT_SPECIFIC };

    memset(tbs, 0, sizeof (X509TbsCertificate));

    status = AJ_ASN1DecodeElements(der, tags, sizeof (tags), 0, &ver, &tbs->serial, &oid, &iss, &utc, &sub, &pub, 3, &ext);
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
    if (!CompareOID(&tmp, OID_SIG_ECDSA_SHA256, sizeof (OID_SIG_ECDSA_SHA256))) {
        return AJ_ERR_INVALID;
    }

    status = DecodeCertificateName(&tbs->issuer, &iss);
    if (AJ_OK != status) {
        return status;
    }
    status = DecodeCertificateTime(&tbs->validity, &utc);
    if (AJ_OK != status) {
        return status;
    }
    status = DecodeCertificateName(&tbs->subject, &sub);
    if (AJ_OK != status) {
        return status;
    }
    status = DecodeCertificatePub(&tbs->publickey, &pub);
    if (AJ_OK != status) {
        return status;
    }
    status = DecodeCertificateExt(&tbs->extensions, &ext);
    if (AJ_OK != status) {
        return status;
    }

    return status;
}

static AJ_Status DecodeCertificateSig(AJ_ECCSignature* signature, DER_Element* der)
{
    AJ_Status status;
    DER_Element seq;
    DER_Element int1;
    DER_Element int2;
    const uint8_t tags[] = { ASN_INTEGER, ASN_INTEGER };

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
    if (KEY_ECC_SZ < int1.size) {
        return AJ_ERR_INVALID;
    }
    if (KEY_ECC_SZ < int2.size) {
        return AJ_ERR_INVALID;
    }

    memset(signature, 0, sizeof (AJ_ECCSignature));
    // Copy into lsb
    memcpy(signature->r + (KEY_ECC_SZ - int1.size), int1.data, int1.size);
    memcpy(signature->s + (KEY_ECC_SZ - int2.size), int2.data, int2.size);

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
    const uint8_t tags1[] = { ASN_SEQ };
    const uint8_t tags2[] = { ASN_SEQ, ASN_SEQ, ASN_BITS };

    AJ_InfoPrintf(("AJ_X509DecodeCertificateDER(certificate=%p, der=%p)\n", certificate, der));

    if ((NULL == certificate) || (NULL == der)) {
        return AJ_ERR_INVALID;
    }

    status = AJ_ASN1DecodeElements(der, tags1, sizeof (tags1), &seq);
    if (AJ_OK != status) {
        return status;
    }
    /* Signed TBS section starts here */
    certificate->raw.data = seq.data;
    status = AJ_ASN1DecodeElements(&seq, tags2, sizeof (tags2), &tbs, &tmp, &sig);
    if (AJ_OK != status) {
        return status;
    }
    certificate->raw.size = tbs.size + (tbs.data - certificate->raw.data);

    status = DecodeCertificateTBS(&certificate->tbs, &tbs);
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
    if (!CompareOID(&oid, OID_SIG_ECDSA_SHA256, sizeof (OID_SIG_ECDSA_SHA256))) {
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
    status = DecodeCertificateSig(&certificate->signature, &sig);

    return status;
}

AJ_Status AJ_X509DecodeCertificatePEM(X509Certificate* certificate, const char* pem)
{
    AJ_Status status;
    const char* beg = pem;
    const char* end;
    size_t len;
    DER_Element der;

    AJ_InfoPrintf(("AJ_X509DecodeCertificatePEM(certificate=%p, pem=%s)\n", certificate, pem));

    beg = strstr(beg, PEM_CERT_BEG);
    if (NULL == beg) {
        AJ_InfoPrintf(("AJ_X509DecodeCertificatePEM(certificate=%p, pem=%s): Missing %s tag\n", certificate, pem, PEM_CERT_BEG));
        return AJ_ERR_INVALID;
    }
    beg = beg + strlen(PEM_CERT_BEG);
    end = strstr(beg, PEM_CERT_END);
    if (NULL == end) {
        AJ_InfoPrintf(("AJ_X509DecodeCertificatePEM(certificate=%p, pem=%s): Missing %s tag\n", certificate, pem, PEM_CERT_END));
        return AJ_ERR_INVALID;
    }
    len = end - beg;
    certificate->der.size = 3 * len / 4;
    certificate->der.data = (uint8_t*) AJ_Malloc(certificate->der.size);
    if (NULL == certificate->der.data) {
        return AJ_ERR_RESOURCES;
    }
    status = AJ_B64ToRaw(beg, len, certificate->der.data, certificate->der.size);
    if (AJ_OK != status) {
        AJ_Free(certificate->der.data);
        certificate->der.data = NULL;
        certificate->der.size = 0;
        return status;
    }
    if ('=' == beg[len - 1]) {
        certificate->der.size--;
    }
    if ('=' == beg[len - 2]) {
        certificate->der.size--;
    }

    /* AJ_X509DecodeCertificateDER modifies its second parameter, so copy the values
     * out so the certificate object itself won't be changed. */
    der.data = certificate->der.data;
    der.size = certificate->der.size;

    return AJ_X509DecodeCertificateDER(certificate, &der);
}

X509CertificateChain* AJ_X509DecodeCertificateChainPEM(const char* pem)
{
    AJ_Status status;
    X509CertificateChain* root = NULL;
    X509CertificateChain* node;
    const char* beg = pem;

    beg = strstr(beg, PEM_CERT_BEG);
    while (beg) {
        node = (X509CertificateChain*) AJ_Malloc(sizeof (X509CertificateChain));
        if (NULL == node) {
            goto Exit;
        }
        /*
         * Push the node on to the head.
         * We do this before decoding so that it is cleaned up in case of error.
         */
        node->next = root;
        root = node;
        status = AJ_X509DecodeCertificatePEM(&node->certificate, beg);
        if (AJ_OK != status) {
            goto Exit;
        }
        /*
         * Look for more certificates, anywhere after the current tag.
         */
        beg = strstr(beg + 1, PEM_CERT_BEG);
    }

    return root;

Exit:
    /* Free the cert chain */
    AJ_X509FreeDecodedCertificateChain(root);
    return NULL;
}

void AJ_X509FreeDecodedCertificateChain(X509CertificateChain* root)
{
    while (root) {
        X509CertificateChain* node = root;
        root = root->next;
        /* Free the der memory if it was created */
        if (node->certificate.der.data) {
            AJ_Free(node->certificate.der.data);
        }
        AJ_Free(node);
    }
}

AJ_Status AJ_X509SelfVerify(const X509Certificate* certificate)
{
    AJ_InfoPrintf(("AJ_X509SelfVerify(certificate=%p)\n", certificate));
    return AJ_X509Verify(certificate, &certificate->tbs.publickey);
}

AJ_Status AJ_X509Verify(const X509Certificate* certificate, const AJ_ECCPublicKey* key)
{
    AJ_InfoPrintf(("AJ_X509Verify(certificate=%p, key=%p)\n", certificate, key));
    return AJ_ECDSAVerify(certificate->raw.data, certificate->raw.size, &certificate->signature, key);
}

AJ_Status AJ_X509VerifyChain(const X509CertificateChain* root, const AJ_ECCPublicKey* key, uint32_t type)
{
    AJ_Status status;
    uint32_t chainValidForType = AJ_CERTIFICATE_UNR_X509;
    uint32_t akiRequired = 0;
    uint32_t isRoot = 1;

    AJ_InfoPrintf(("AJ_X509VerifyChain(root=%p, key=%p, type=%x)\n", root, key, type));

    /* Certificates must have an AKI if they are membership or ID certs.
     * Unrestricted certs are both, so they require an AKI as well.
     * We don't check for the AKI on the root certificate.
     */
    if ((type == AJ_CERTIFICATE_IDN_X509) ||
        (type == AJ_CERTIFICATE_MBR_X509) ||
        (type == AJ_CERTIFICATE_UNR_X509)) {
        akiRequired = 1;
    }

    while (root) {
        if (key) {
            status = AJ_X509Verify(&root->certificate, key);
            if (AJ_OK != status) {
                return status;
            }
        }
        /* This assertion makes sure invalid certificates will never be allowed, by making sure the bit
         * overlap between the internal representations for them and unrestricted certificates is zero,
         * to catch problems if the values of these constants are ever changed in the future.
         */
        AJ_ASSERT((AJ_CERTIFICATE_UNR_X509 & AJ_CERTIFICATE_INV_X509) == 0);
        if ((chainValidForType & root->certificate.tbs.extensions.type) != root->certificate.tbs.extensions.type) {
            AJ_InfoPrintf(("AJ_X509VerifyChain(root=%p, key=%p, type=%x): Certificate fails transitive EKU check; chain so far is valid for type %X, current certificate has type %X\n", root, key, type, chainValidForType, root->certificate.tbs.extensions.type));
            return AJ_ERR_SECURITY;
        }
        chainValidForType &= root->certificate.tbs.extensions.type;

        if (!isRoot && akiRequired && (root->certificate.tbs.extensions.aki.size == 0)) {
            AJ_InfoPrintf(("AJ_X509VerifyChain(root=%p, key=%p, type=%x): Certificate is missing AKI, but the certificate type requires it to be present.\n", root, key, type));
            return AJ_ERR_SECURITY;
        }

        /* The subject field of the current certificate must equal the issuer field of the next certificate
         * in the chain.
         */
        if (NULL != root->next) {
            if (!AJ_X509CompareNames(root->certificate.tbs.subject, root->next->certificate.tbs.issuer)) {
                AJ_InfoPrintf(("AJ_X509VerifyChain(root=%p, key=%p, type=%x): Subject/Issuer name mismatch\n", root, key, type));
                return AJ_ERR_SECURITY;
            }
            if (0 == root->certificate.tbs.extensions.ca) {
                AJ_InfoPrintf(("AJ_X509VerifyChain(root=%p, key=%p, type=%x): Issuer is not a CA\n", root, key, type));
                return AJ_ERR_SECURITY;
            }
        } else {
            /* This is the end entity cert. It must be the expected type if one was specified. */
            if (type && type != root->certificate.tbs.extensions.type) {
                AJ_InfoPrintf(("AJ_X509VerifyChain(root=%p, key=%p, type=%x): End entity certificate has incorrect EKU\n", root, key, type));
                return AJ_ERR_SECURITY;
            }
        }
        key = &root->certificate.tbs.publickey;
        root = root->next;
        isRoot = 0;
    }

    return AJ_OK;
}

void AJ_X509ChainFree(X509CertificateChain* root)
{
    X509CertificateChain* node;

    while (root) {
        node = root;
        root = root->next;
        AJ_Free(node);
    }
}

AJ_Status AJ_X509ChainMarshal(X509CertificateChain* root, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    X509CertificateChain* node;

    /*
     * X509CertificateChain is root first.
     * The wire protocol requires leaf first,
     * reverse it here, then reverse it back after marshalling.
     */
    root = AJ_X509ReverseChain(root);
    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    node = root;
    while (node) {
        status = AJ_MarshalArgs(msg, "(yay)", CERT_FMT_X509_DER, node->certificate.der.data, node->certificate.der.size);
        if (AJ_OK != status) {
            goto Exit;
        }
        node = node->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container);
    if (AJ_OK != status) {
        goto Exit;
    }

Exit:
    root = AJ_X509ReverseChain(root);
    return status;
}

AJ_Status AJ_X509ChainUnmarshal(X509CertificateChain** root, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    uint8_t fmt;
    DER_Element der;
    X509CertificateChain* head = NULL;
    X509CertificateChain* node = NULL;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalArgs(msg, "(yay)", &fmt, &der.data, &der.size);
        if (AJ_OK != status) {
            break;
        }
        if (CERT_FMT_X509_DER != fmt) {
            AJ_WarnPrintf(("AJ_X509ChainUnmarshal(root=%p, msg=%p): Certificate format unknown\n", root, msg));
            goto Exit;
        }
        node = (X509CertificateChain*) AJ_Malloc(sizeof (X509CertificateChain));
        if (NULL == node) {
            goto Exit;
        }
        node->certificate.der.size = der.size;
        node->certificate.der.data = der.data;
        node->next = head;
        head = node;
        status = AJ_X509DecodeCertificateDER(&node->certificate, &der);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_X509ChainUnmarshal(root=%p, msg=%p): Certificate decode failed\n", root, msg));
            goto Exit;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);
    if (AJ_OK != status) {
        goto Exit;
    }

    *root = head;
    return status;

Exit:
    /* Free the cert chain */
    AJ_X509ChainFree(head);
    return AJ_ERR_FAILURE;
}

AJ_Status AJ_X509ChainToBuffer(X509CertificateChain* root, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    AJ_LocalMsg(&bus, &hdr, &msg, "a(yay)", field->data, field->size);
    status = AJ_X509ChainMarshal(root, &msg);
    field->size = bus.sock.tx.writePtr - field->data;

    return status;
}

AJ_Status AJ_X509ChainFromBuffer(X509CertificateChain** root, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    AJ_LocalMsg(&bus, &hdr, &msg, "a(yay)", field->data, field->size);
    status = AJ_X509ChainUnmarshal(root, &msg);

    return status;
}

X509Certificate* AJ_X509LeafCertificate(X509CertificateChain* root)
{
    if (NULL == root) {
        return NULL;
    }
    while (root->next) {
        root = root->next;
    }
    return &root->certificate;
}

X509CertificateChain* AJ_X509ReverseChain(X509CertificateChain* root)
{
    X509CertificateChain* temp;
    X509CertificateChain* last = NULL;
    while (root) {
        temp = root->next;
        root->next = last;
        last = root;
        root = temp;
    }
    return last;
}
