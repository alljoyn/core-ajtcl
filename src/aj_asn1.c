/**
 * @file
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
#define AJ_MODULE ASN1

#include <stdarg.h>
#include "aj_asn1.h"
#include "aj_debug.h"

#ifndef NDEBUG
uint8_t dbgASN1 = 0;
#endif

static AJ_Status DecodeLength(DER_Element* der, DER_Element* out)
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
        while ((n--) && (der->size--)) {
            len = (len << 8) + *(der->data)++;
        }
    }
    if (len > der->size) {
        return AJ_ERR_INVALID;
    }
    out->size = len;
    out->data = der->data;

    return AJ_OK;
}

AJ_Status AJ_ASN1DecodeElement(DER_Element* der, uint8_t tag, DER_Element* out)
{
    uint8_t tmp;

    AJ_InfoPrintf(("AJ_ASN1DecodeElement(der=%p, tag=%x, out=%p)\n", der, tag, out));

    if ((NULL == der) || (NULL == out)) {
        return AJ_ERR_INVALID;
    }
    if ((NULL == der->data) || (0 == der->size)) {
        return AJ_ERR_INVALID;
    }

    /*
     * Decode tag and check it is what we expect
     */
    tmp = *(der->data)++;
    der->size--;
    if (ASN_CONTEXT_SPECIFIC != (tmp & ASN_CONTEXT_SPECIFIC)) {
        tmp &= 0x1F;
    }
    if (tmp != tag) {
        return AJ_ERR_INVALID;
    }
    /*
     * Decode size
     */
    if (AJ_OK != DecodeLength(der, out)) {
        return AJ_ERR_INVALID;
    }
    der->data += out->size;
    der->size -= out->size;

    return AJ_OK;
}

AJ_Status AJ_ASN1DecodeElements(DER_Element* der, uint8_t* tags, size_t len, ...)
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
    va_end(argp);

    /*
     * Should all be consumed
     */
    if (len || der->size) {
        status = AJ_ERR_INVALID;
    }

    return status;
}

