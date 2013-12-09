#ifndef _AJ_DEBUG_H
#define _AJ_DEBUG_H
/******************************************************************************
 * Copyright (c) 2012-2013, AllSeen Alliance. All rights reserved.
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
 * @defgroup aj_debug Debug Logging
 * @{
 * @file aj_debug.h
 * This file contains the debug logging support for the Thin Client.
 *
 * The Thin Client runs on very disparate devices.  We provide off-target
 * development environments such as Linux and Windows to allow development of
 * thin client applications.  These environments have a relatively large amount
 * of resources available to dedicate to ease of debugging (which is the reason
 * one would run in those environments in the first place).  When Thin Client
 * applications are run on target, they run in very restrictive environments
 * where rich debug logging support may not be possible or desirable.  The debug
 * logging module allows capable targets to provide convenient debug logging
 * functions that are easily configured by shell environment variable; and it
 * allows for similar configuration via target memory global variables.  In
 * extremely constrained targets that simply cannot afford the memory for log
 * strings, the debug logging facility can be completely disabled or enabled
 * selectively per-module if desired.
 *
 * At the highest level, if NDEBUG is defined, the entire debug logging module is
 * disabled and no resources will be dedicated to debug support.
 *
 * A slightly finer grain control is accomplished by controlling the definition
 * of the macro AJ_DEBUG_RESTRICT.  There are five levels of debug output
 * currently defined: AJ_DEBUG_OFF, AJ_DEBUG_ERROR, AJ_DEBUG_WARN,
 * AJ_DEBUG_INFO, AJ_DEBUG_DUMP and AJ_DEBUG_ALL.  See the documentation for
 * each of these macros for definitions.  If NDEBUG is not defined,
 * AJ_DEBUG_RESTRICT allows one to control which debug strings are compiled into
 * the codebase and are therefore printed.  If, for example, one is running on a
 * target whcih cannot store all debug strings, one might want to define
 * AJ_DEBUG_RESTRICT as AJ_DEBUG_WARN which would only compile and print error
 * messages across all modules.  AJ_DEBUG_RESTRICT defaults to AJ_DEBUG_INFO
 * which only allows warning and error messages to be compiled.  This is to
 * avoid intruducing large numbers of strings in the default case.
 *
 * If NDEBUG is not defined, and AJ_DEBUG_RESTRICT allows some debug logging to
 * be compiled, the next level of granularity is a per-module enable.  In the
 * Thin Client, a module essentially corresponds to a source file.  For example,
 * the file aj_bus.h has a defgroup in doxygen to associate it with the aj_bus
 * documentation module.  Similarly the file aj_bus.c defines AJ_MODULE as BUS
 * delaring that the current module is called BUS.  The per-module granularity
 * of debug logging depends on those definitions.
 *
 * Since writing and debugging of Thin Client programs is expected to happen on
 * off-target platforms, we want to provide easy-to-use mechanisms that can be
 * used to turn debugging on and off.  We chose to do this in a way similar to
 * the standard client.  We use ER_DEBUG_ environment variables.
 *
 * If NDEBUG is not defined and AJ_DEBUG_RESTRICT allows, error and warning
 * messages are always printed.  If one does the shell equivalent of "export
 * ER_DEBUG_ALL=1" then all messages will be printed.  Note that the value "1"
 * in the environment variable means enable and "0" means disable.  We do not
 * encode the restriction level in environment variables since AJ_DEBUG_RESTRICT
 * compiles the code in or out.
 *
 * Again, similarly to the standard client, if one does the shell equivalent of
 * ER_DEBUG_<module name> then debug logging for the specified module is
 * enabled.  For example, to get informational messages from aj_bus.c, one would
 * enable loging on the corresponding module using "export ER_DEBUG_BUS=1" (on
 * Linux).  Disabling logging would be done by setting the appropriate environment
 * variable value to zero (e.g., "export ER_DEBUG_BUS=0").
 *
 * If, however, one moves to a target platform proper, chances are that there
 * will be no shell and no environment variables -- another mechanism is
 * required.  In that case, for each AJ_MODULE definition, there is a
 * corresponding global variable that is named dbg<module name>.  For example,
 * the case of the file aj_bus.c, the corresponding module is BUS, and therefore
 * there will be a global variable (uint8_t) named dbgBUS that will control the
 * debug output exactly as the ER_DEBUG_BUS environment variable did (there is
 * also a variable dbgALL that corresponds to the ER_DEBUG_ALL variable).  In
 * order to enable ALL logging using this mechanism, one would (in the case of gdb)
 * "set dbgALL=1".  In order to enable logging in aj_bus.c, one would set the
 * dbgBUS global variable to 1.  Disabling logging would be done by setting the
 * appropriate global variable value to zero (e.g., "set dbgALL=0").
 */

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
void _AJ_DumpMsg(const char* tag, AJ_Message* msg, uint8_t body);

/**
 * Dump raw data
 *
 * @param tag       tag name of message
 * @param data      start addres to dump
 * @param len       length to dump
 */
void _AJ_DumpBytes(const char* tag, const uint8_t* data, uint32_t len);

/**
 * Threshold levels for debug ouput.  Works in conjunction with AJ_DEBUG_RESTRICT
 */
#define AJ_DEBUG_OFF   0  /**< Supresses all debug output */
#define AJ_DEBUG_ERROR 1  /**< Only display debug messages at the error level */
#define AJ_DEBUG_WARN  2  /**< Display warning and error messages */
#define AJ_DEBUG_INFO  3  /**< Display info, warning, and error messages */
#define AJ_DEBUG_DUMP  4  /**< Display byte-by-byte dumps */
#define AJ_DEBUG_ALL   5  /**< A placeholder level for AJ_DEBUG_RESTRICT */

typedef uint32_t AJ_DebugLevel;

/**
 * We allow the verbosity of debug output to be controlled programatically using
 * threshold levels defined above.  The macro AJ_DEBUG_RESTRICT is used in the sense
 * of restricting (not compiling in) messages of the given verbosity and above.
 *
 * By default, all messages of all verbosity above info are not compiled into the
 * code (by definining AJ_DEBUG_RESTRICT to be AJ_DEBUG_INFO).
 *
 * It may be the case that your platform which can absorb the added overhead of
 * large numbers of debug strings.  For this case, redefine the macro
 * AJ_DEBUG_RESTRICT to, for example, AJ_DEBUG_ALL to compile in all debug
 * messages into the code.
 *
 * If desired this variable can be set per-file.
 */
#ifndef AJ_DEBUG_RESTRICT
#define AJ_DEBUG_RESTRICT AJ_DEBUG_INFO
#endif

/**
 * Set this value to control the debug ouput threshold level. The default is AJ_DEBUG_ERROR
 */
AJ_EXPORT extern AJ_DebugLevel AJ_DbgLevel;
AJ_EXPORT extern uint8_t dbgALL;

extern int _AJ_DbgEnabled(char* module);

/**
 * Internal debug printf function. Don't call this directly, use the AJ_*Printf() macros.
 *
 * @param level The level associated with this debug print
 * @param file  File name for file calling this function
 * @param line  Line number for line this function was called from
 */
int _AJ_DbgHeader(AJ_DebugLevel level, const char* file, int line);

#define QUOTE(x) # x
#define STR(x) QUOTE(x)

#define CONCAT(x, y) x ## y
#define MKVAR(x, y) CONCAT(x, y)

#if AJ_DEBUG_RESTRICT > AJ_DEBUG_ERROR
/**
 * Print an error message.  Error messages may be supressed by AJ_DEBUG_RESTRICT
 *
 * @param msg  A format string and arguments
 */
#define AJ_ErrPrintf(msg) \
    do { \
        if (_AJ_DbgHeader(AJ_DEBUG_ERROR, __FILE__, __LINE__)) { AJ_Printf msg; } \
    } while (0)
#else
#define AJ_ErrPrintf(_msg)
#endif

#if AJ_DEBUG_RESTRICT > AJ_DEBUG_WARN
/**
 * Print a warning message. Warnings may be suppressed by AJ_DEBUG_RESTRICT
 *
 * @param msg  A format string and arguments
 */
#define AJ_WarnPrintf(msg) \
    do { \
        if (_AJ_DbgHeader(AJ_DEBUG_WARN, __FILE__, __LINE__)) { AJ_Printf msg; } \
    } while (0)
#else
#define AJ_WarnPrintf(_msg)
#endif

#if AJ_DEBUG_RESTRICT > AJ_DEBUG_INFO
/**
 * Print an informational message.  Informational messages may be suppressed by
 * AJ_DEBUG_RESTRICT or by the module selection (global memory value or shell
 * environment variable) mechanism.
 *
 * @param msg  A format string and arguments
 */
#define AJ_InfoPrintf(msg) \
    do { \
        if (dbgALL || MKVAR(dbg, AJ_MODULE) || _AJ_DbgEnabled(STR(AJ_MODULE))) { \
            if (_AJ_DbgHeader(AJ_DEBUG_INFO, __FILE__, __LINE__)) { AJ_Printf msg; } \
        } \
    } while (0)
#else
#define AJ_InfoPrintf(_msg)
#endif

#if AJ_DEBUG_RESTRICT > AJ_DEBUG_DUMP
/**
 * Dump the bytes in a buffer in a human readable way.  Byte dumps messages may
 * be suppressed by AJ_DEBUG_RESTRICT or by the module selection (global memory
 * value or shell environment variable) mechanism.
 *
 * @param msg A format string
 * and arguments
 */
#define AJ_DumpBytes(tag, data, len) \
    do { \
        if (MKVAR(dbg, AJ_MODULE) || _AJ_DbgEnabled(STR(AJ_MODULE))) { _AJ_DumpBytes(tag, data, len); } \
    } while (0)
#else
#define AJ_DumpBytes(tag, data, len)
#endif

#if AJ_DEBUG_RESTRICT > AJ_DEBUG_DUMP
/**
 * Print a human readable summary of a message.  Message dumps messages may be
 * suppressed by AJ_DEBUG_RESTRICT or by the module selection (global memory
 * value or shell environment variable) mechanism.
 *
 * @param msg  A format string and arguments
 */
#define AJ_DumpMsg(tag, msg, body) \
    do { \
        if (MKVAR(dbg, AJ_MODULE) || _AJ_DbgEnabled(STR(AJ_MODULE))) { _AJ_DumpMsg(tag, msg, body); } \
    } while (0)
#else
#define AJ_DumpMsg(tag, msg, body)
#endif

#else

#define AJ_DumpMsg(tag, msg, body)
#define AJ_DumpBytes(tag, data, len)
#define AJ_ErrPrintf(_msg)
#define AJ_WarnPrintf(_msg)
#define AJ_InfoPrintf(_msg)

#endif

/**
 * Utility function that converts numerical status to a readable string
 *
 * @param status  A status code
 */
AJ_EXPORT const char* AJ_StatusText(AJ_Status status);

/**
 * @}
 */
#endif
