#ifndef _AJ_TARGET_H
#define _AJ_TARGET_H
/**
 * @file WSL target macros and includes
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

#include <stdlib.h>

#define AJ_EXPORT

#include <stdint.h>
#include <stddef.h>

#include "aj_target_rtos.h"
#include "aj_target_platform.h"
#include <string.h>
#include "assert.h"
#include "aj_connect.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

#define WORD_ALIGN(x) ((x & 0x3) ? ((x >> 2) + 1) << 2 : x)
#define HOST_IS_LITTLE_ENDIAN  1
#define HOST_IS_BIG_ENDIAN     0
#define HOST_ENDIANESS          AJ_LITTLE_ENDIAN

#ifndef NDEBUG
extern uint8_t dbgCONFIGUREME;
extern uint8_t dbgINIT;
extern uint8_t dbgNET;
extern uint8_t dbgTARGET_CRYPTO;
extern uint8_t dbgTARGET_NVRAM;
extern uint8_t dbgTARGET_SERIAL;
extern uint8_t dbgTARGET_TIMER;
extern uint8_t dbgTARGET_UTIL;
#endif

#define AJ_ASSERT(x) assert(x)


/*
 * AJ_Reboot() is a NOOP on this platform
 */
#define AJ_Reboot() _AJ_Reboot()

#define AJ_CreateNewGUID AJ_RandBytes

#define AJ_GetDebugTime(x) AJ_ERR_RESOURCES

#ifdef __cplusplus
}
#endif

#endif