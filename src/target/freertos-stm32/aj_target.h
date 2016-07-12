#ifndef _AJ_TARGET_H
#define _AJ_TARGET_H
/**
 * @file WSL target macros and includes
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
 ******************************************************************************/
#define AJ_EXPORT

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#include <ajtcl/aj_target_platform.h>
#include <ajtcl/aj_target_rtos.h>

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

/**
 * Macro to mark a function deprecated, with a date.
 * Include the date of the AllJoyn release when applying this macro (date format: YY.MM).
 */
#if (__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1))
#define AJ_DEPRECATED_ON(func, date) __attribute__((deprecated)) func /**< mark a function as deprecated in gcc. */
#else
#define AJ_DEPRECATED_ON(func, date) func  /**< not all gcc versions support the deprecated attribute. */
#endif

#endif
