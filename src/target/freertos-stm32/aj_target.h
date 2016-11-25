#ifndef _AJ_TARGET_H
#define _AJ_TARGET_H
/**
 * @file WSL target macros and includes
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
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

#define GCC_VERSION ((__GNUC__ * 10000) + (__GNUC_MINOR__ * 100) + __GNUC_PATCHLEVEL__)
/**
 * Macro to mark a function deprecated, with a date.
 * Include the date of the AllJoyn release when applying this macro (date format: YY.MM).
 */
#if (__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1))
#define AJ_DEPRECATED_ON(func, date) __attribute__((deprecated)) func /**< mark a function as deprecated in gcc. */

#if (GCC_VERSION >= 40500L)
#define AJ_DEPRECATED_MSG(func, msg, date) func __attribute__((deprecated(msg))) /**< same as AJ_DEPRECATED_ON, but with user-defined text message to be displayed. */
#else
#define AJ_DEPRECATED_MSG(func, msg, date) AJ_DEPRECATED_ON(func, date) /**< gcc versions older than 4.5 do not support the text message. */
#endif // GCC version >= 4.5

#else
#define AJ_DEPRECATED_ON(func, date) func /**< not all gcc versions support the deprecated attribute. */
#define AJ_DEPRECATED_MSG(func, msg, date) func /**< not all gcc versions support the deprecated attribute. */
#endif // GCC version >= 3.1

#endif