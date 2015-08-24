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
#define AJ_MODULE CRYPTO_UTIL

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_config.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCRYPTO_UTIL = 0;
#endif

AJ_Status AJ_RandHex(char* randBuf, uint32_t bufLen, uint32_t len)
{
    AJ_RandBytes((uint8_t*)randBuf, len);
    return AJ_RawToHex((const uint8_t*) randBuf, len, randBuf, bufLen, FALSE);
}

int AJ_Crypto_Compare(const void* buf1, const void* buf2, size_t count)
{
    size_t i = 0;
    uint8_t different = 0;

    AJ_ASSERT(buf1 != NULL);
    AJ_ASSERT(buf2 != NULL);

    /* This loop uses the same number of cycles for any two buffers of size count. */
    for (i = 0; i < count; i++) {
        different |= ((uint8_t*)buf1)[i] ^ ((uint8_t*)buf2)[i];
    }

    return (int)different;
}
