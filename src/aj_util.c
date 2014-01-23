/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012, 2014 AllSeen Alliance. All rights reserved.
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
#include "aj_util.h"
#include "aj_version.h"

#define AJ_TO_STRING(x) # x
#define AJ_VERSION_STRING(a, b, c, d) AJ_TO_STRING(a) "." AJ_TO_STRING(b) "." AJ_TO_STRING(c) " Tag " AJ_TO_STRING(d) "\0"
const char* AJ_GetVersion()
{
    static const char VERSION[] = AJ_VERSION_STRING(AJ_MAJOR_VERSION, AJ_MINOR_VERSION, AJ_RELEASE_VERSION, AJ_RELEASE_TAG);
    return &VERSION[0];
}

static uint8_t A2H(char hex, AJ_Status* status)
{
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    }
    hex |= 0x20;
    if (hex >= 'a' && hex <= 'f') {
        return 10 + hex - 'a';
    } else if (hex >= 'A' && hex <= 'F') {
        return 10 + hex - 'A';
    } else {
        *status = AJ_ERR_INVALID;
        return 0;
    }
}

int32_t AJ_StringFindFirstOf(const char* str, char* chars)
{
    if (str) {
        const char* p = str;
        do {
            const char* c = chars;
            while (*c) {
                if (*p == *c++) {
                    return (int32_t)(p - str);
                }
            }
        } while (*(++p));
    }
    return -1;
}

AJ_Status AJ_RawToHex(const uint8_t* raw, size_t rawLen, char* hex, size_t hexLen, uint8_t lower)
{
    static const char nibble_upper[] = "0123456789ABCDEF";
    static const char nibble_lower[] = "0123456789abcdef";
    const char* nibble = lower ? nibble_lower : nibble_upper;
    char* h = hex + 2 * rawLen;
    const uint8_t* a = raw + rawLen;

    if ((2 * rawLen + 1) > hexLen) {
        return AJ_ERR_RESOURCES;
    }
    h[0] = '\0';
    /*
     * Running backwards encode each byte in inStr as a pair of ascii hex digits.
     * Going backwards allows the raw and hex buffers to be the same buffer.
     */
    while (rawLen--) {
        uint8_t n = *(--a);
        h -= 2;
        h[0] = nibble[n >> 4];
        h[1] = nibble[n & 0xF];
    }
    return AJ_OK;
}

AJ_Status AJ_HexToRaw(const char* hex, size_t hexLen, uint8_t* raw, size_t rawLen)
{
    AJ_Status status = AJ_OK;
    char* p = (char*)raw;
    size_t sz = hexLen ? hexLen : strlen(hex);
    size_t i;

    /*
     * Length of encoded hex must be an even number
     */
    if (sz & 1) {
        return AJ_ERR_UNEXPECTED;
    }
    if (rawLen < (sz / 2)) {
        return AJ_ERR_RESOURCES;
    }
    for (i = 0; (i < sz) && (status == AJ_OK); i += 2, hex += 2) {
        *p++ = (A2H(hex[0], &status) << 4) | A2H(hex[1], &status);
    }
    return status;
}
