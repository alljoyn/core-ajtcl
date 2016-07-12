/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
 ******************************************************************************/

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE TARGET_CRYPTO

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_debug.h>

#include <windows.h>
#include <wincrypt.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgTARGET_CRYPTO = 0;
#endif

void AJ_RandBytes(uint8_t* rand, uint32_t len)
{
    HCRYPTPROV hProvider;
    CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    CryptGenRandom(hProvider, len, rand);
    CryptReleaseContext(hProvider, 0);
}

