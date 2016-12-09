#ifndef _AJ_DEBUG_H
#define _AJ_DEBUG_H
/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
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

#include "aj_target.h"
#include "aj_msg.h"

#ifndef NDEBUG

/**
 * Dump message name and content. if body is true, dump raw data
 *
 * @param tag       tag name of message
 * @param msg       message header
 * @param body      if true, dump raw data
 */
void AJ_DumpMsg(const char* tag, AJ_Message* msg, uint8_t body);

/**
 * Dump raw data
 *
 * @param tag       tag name of message
 * @param data      start addres to dump
 * @param len       length to dump
 */
void AJ_DumpBytes(const char* tag, const uint8_t* data, uint32_t len);

/**
 * Threshold levels for debug ouput
 */
typedef enum {
    AJ_DEBUG_OFF,   /**< Supresses all debug output */
    AJ_DEBUG_ERROR, /**< Only display debug messages at the error level */
    AJ_DEBUG_WARN,  /**< Display warning and error messages */
    AJ_DEBUG_INFO   /**< Display info, warning, and error messages */
} AJ_DebugLevel;


/**
 * Set this value to control the debug ouput threshold level. The default is AJ_DEBUG_ERROR
 */
extern AJ_DebugLevel AJ_DbgLevel;

/**
 * Internal debug printf function. Don't call this directly, use the AJ_*Printf() macros.
 *
 * @param level The level associated with this debug print
 * @param file  File name for file calling this function
 * @param line  Line number for line this function was called from
 */
int _AJ_DbgHeader(AJ_DebugLevel level, const char* file, int line);

/**
 * Print an error message
 *
 * @param msg  A format string and arguments
 */
#define AJ_ErrPrintf(msg) \
    do { \
        if (_AJ_DbgHeader(AJ_DEBUG_ERROR, __FILE__, __LINE__)) { AJ_Printf msg; } \
    } while (0)

/**
 * Print a warning message. Warnings are only printed if the current
 *
 * @param msg  A format string and arguments
 */
#define AJ_WarnPrintf(msg) \
    do { \
        if (_AJ_DbgHeader(AJ_DEBUG_WARN, __FILE__, __LINE__)) { AJ_Printf msg; } \
    } while (0)

/**
 * Print an informational message
 *
 * @param msg  A format string and arguments
 */
#define AJ_InfoPrintf(msg) \
    do { \
        if (_AJ_DbgHeader(AJ_DEBUG_INFO, __FILE__, __LINE__)) { AJ_Printf msg; } \
    } while (0)

#else

#define AJ_DumpMsg(tag, msg, body)
#define AJ_DumpBytes(tag, data, len)
#define AJ_ErrPrintf(_msg)
#define AJ_WarnPrintf(_msg)
#define AJ_InfoPrintf(_msg)

#endif

/**
 * Debug utility function that converts numerical status to a readable string
 *
 * @param status  A status code
 */
const char* AJ_StatusText(AJ_Status status);

#endif