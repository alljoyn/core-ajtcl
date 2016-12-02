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
#define AJ_MODULE BUFIO

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_status.h>
#include <ajtcl/aj_bufio.h>
#include <ajtcl/aj_debug.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgBUFIO = 0;
#endif

void AJ_IOBufInit(AJ_IOBuffer* ioBuf, uint8_t* buffer, uint32_t bufLen, uint8_t direction, void* context)
{
    ioBuf->bufStart = buffer;
    ioBuf->bufSize = bufLen;
    ioBuf->readPtr = buffer;
    ioBuf->writePtr = buffer;
    ioBuf->direction = direction;
    ioBuf->context = context;
}

void AJ_IOBufRebase(AJ_IOBuffer* ioBuf, size_t preserve)
{
    int32_t unconsumed = AJ_IO_BUF_AVAIL(ioBuf);
    /*
     * Move any unconsumed data to the start of the I/O buffer
     */
    if (unconsumed) {
        memmove(ioBuf->bufStart + preserve, ioBuf->readPtr, unconsumed);
    }

    ioBuf->readPtr = ioBuf->bufStart + preserve;
    ioBuf->writePtr = ioBuf->bufStart + preserve + unconsumed;
}