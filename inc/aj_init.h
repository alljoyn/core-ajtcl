#ifndef _AJ_INIT_H
#define _AJ_INIT_H

/**
 * @file aj_init.h
 * @defgroup aj_init Initialization
 * @{
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
 ******************************************************************************/

#include <ajtcl/aj_target.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialization for AllJoyn. This function should be called before calling any
 * other AllJoyn APIs.
 */
AJ_EXPORT void AJ_Initialize(void);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
