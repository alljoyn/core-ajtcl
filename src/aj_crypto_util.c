/**
 * @file
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