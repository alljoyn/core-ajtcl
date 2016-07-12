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
#define AJ_MODULE INIT

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_init.h>
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_guid.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_connect.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgINIT = 0;
#endif

static uint8_t initialized = FALSE;

void AJ_Initialize(void)
{
    AJ_GUID localGuid;
    if (!initialized) {
        initialized = TRUE;
        AJ_NVRAM_Init();
        /*
         * This will seed the random number generator
         */
        AJ_RandBytes(NULL, 0);
        /*
         * This will initialize credentials if needed
         */
        AJ_GetLocalGUID(&localGuid);

        /*
         * Clear the Routing Node black list
         */
        AJ_InitRoutingNodeBlacklist();

        AJ_InitRoutingNodeResponselist();
    }
}
