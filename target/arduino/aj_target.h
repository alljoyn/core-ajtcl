#ifndef _AJ_TARGET_H
#define _AJ_TARGET_H
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

#define AJ_EXPORT

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef signed char int8_t;           /** 8-bit signed integer */
typedef unsigned char uint8_t;        /** 8-bit unsigned integer */
typedef signed long long int64_t;     /** 64-bit signed integer */
typedef unsigned long long uint64_t;  /** 64-bit unsigned integer */

typedef uint16_t suint32_t;  /* amount of data sent into a socket */


#include <string.h>
#include <malloc.h>
#include <assert.h>

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

// Begin Memory Diagnostics
static const char* ramstart = (char*)0x20070000;
static const char* ramend = (char*)0x20088000;
extern char _end;

inline int stack_used() {
    register char* stack_ptr asm ("sp");
    return (ramend - stack_ptr);
}

inline int static_used() {
    return (&_end - ramstart);
}

inline int heap_used() {
    struct mallinfo mi = mallinfo();
    return (mi.uordblks);
}

void ram_diag();

// End Memory Diagnostics

#define WORD_ALIGN(x) ((x & 0x3) ? ((x >> 2) + 1) << 2 : x)

#define HOST_IS_LITTLE_ENDIAN  TRUE
#define HOST_IS_BIG_ENDIAN     FALSE

#ifdef WIFI_UDP_WORKING
    #include <WiFi.h>
    #include <WiFiUdp.h>
#else
    #include <Ethernet.h>
    #include <EthernetUdp.h>
#endif

#define AJ_Printf(fmat, ...) \
    do { printf(fmat, ## __VA_ARGS__); } while (0)


#ifndef NDEBUG

extern uint8_t dbgCONFIGUREME;
extern uint8_t dbgINIT;
extern uint8_t dbgNET;
extern uint8_t dbgTARGET_CRYPTO;
extern uint8_t dbgTARGET_NVRAM;
extern uint8_t dbgTARGET_UTIL;

#endif

#define AJ_ASSERT(x) assert(x)

/*
 * AJ_Reboot() is a NOOP on this platform
 */
#define AJ_Reboot()

#define AJ_CreateNewGUID AJ_RandBytes

#define AJ_GetDebugTime(x) AJ_ERR_RESOURCES

#endif