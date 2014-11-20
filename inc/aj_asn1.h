#ifndef _AJ_ASN1_H
#define _AJ_ASN1_H
/**
 * @file aj_asn1.h
 * @defgroup aj_asn1 ASN.1 decoding
 * @{
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

#include "aj_target.h"
#include "aj_status.h"

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
#define ASN_CONTEXT_SPECIFIC 0xA0

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
AJ_Status AJ_ASN1DecodeElements(DER_Element* der, uint8_t* tags, size_t len, ...);

/**
 * @}
 */
#endif
