/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
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

#include "Arduino.h"
#include <time.h>
#include <stdint.h>
#include <ajtcl/aj_target.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_debug.h>

typedef struct time_struct {

    /* The number of milliseconds in the time. */
    uint32_t milliseconds;

} TIME_STRUCT;

void AJ_Sleep(uint32_t time)
{
    delay(time);
}

uint32_t AJ_GetElapsedTime(AJ_Time* timer, uint8_t cumulative)
{
    uint32_t elapsed;
    TIME_STRUCT now;

    now.milliseconds =  millis();
    elapsed = (uint32_t)now.milliseconds - (timer->seconds * 1000 + timer->milliseconds);  // watch for wraparound
    if (!cumulative) {
        timer->seconds = (uint32_t)(now.milliseconds / 1000);
        timer->milliseconds = (uint16_t)(now.milliseconds % 1000);
    }
    return elapsed;
}
void AJ_InitTimer(AJ_Time* timer)
{
    TIME_STRUCT now;
    now.milliseconds =  millis();
    timer->seconds = (uint32_t)(now.milliseconds / 1000);
    timer->milliseconds = (uint16_t)(now.milliseconds % 1000);
}

uint64_t AJ_DecodeTime(char* der, const char* fmt)
{
    time_t ret;
    char* tz;

    struct tm tm;
    if (!strptime(der, fmt, &tm)) {
        return 0;
    }

    /*
     * mktime() assumes that tm is in local time but it is in UTC.
     * So we set the time zone to UTC first, and reset it after the
     * call to mktime().
     */
    tz = getenv("TZ");
    setenv("TZ", "", 1);
    tzset();
    ret = mktime(&tm);
    if (tz) {
        setenv("TZ", tz, 1);
    } else {
        unsetenv("TZ");
    }
    tzset();

    if (ret == -1) {
        return 0;
    }
    return (uint64_t) ret;
}

void* AJ_Malloc(size_t sz)
{
    return malloc(sz);
}

void* AJ_Realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

void AJ_Free(void* mem)
{
    if (mem) {
        free(mem);
    }
}

void AJ_MemZeroSecure(void* s, size_t n)
{
    volatile unsigned char* p = (unsigned char*) s;
    while (n--) *p++ = '\0';
    return;
}

void ram_diag()
{
    AJ_AlwaysPrintf(("SRAM usage (stack, heap, static): %d, %d, %d\n",
                     stack_used(),
                     heap_used(),
                     static_used()));
}

uint8_t AJ_StartReadFromStdIn()
{
    return FALSE;
}

uint8_t AJ_StopReadFromStdIn()
{
    return FALSE;
}

uint16_t AJ_ByteSwap16(uint16_t x)
{
#ifdef __GNUC__
    return __builtin_bswap16(x);
#else
    return ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
#endif
}

uint32_t AJ_ByteSwap32(uint32_t x)
{
#ifdef __GNUC__
    return __builtin_bswap32(x);
#else
    return ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8)
           | ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24);
#endif
}

uint64_t AJ_ByteSwap64(uint64_t x)
{
#ifdef __GNUC__
    return __builtin_bswap64(x);
#else
    return ((x & UINT64_C(0x00000000000000FF)) << 56)
           | ((x & UINT64_C(0x000000000000FF00)) << 40)
           | ((x & UINT64_C(0x0000000000FF0000)) << 24)
           | ((x & UINT64_C(0x00000000FF000000)) <<  8)
           | ((x & UINT64_C(0x000000FF00000000)) >>  8)
           | ((x & UINT64_C(0x0000FF0000000000)) >> 24)
           | ((x & UINT64_C(0x00FF000000000000)) >> 40)
           | ((x & UINT64_C(0xFF00000000000000)) >> 56);
#endif
}

char* AJ_GetCmdLine(char* buf, size_t num)
{
    if (Serial.available() > 0) {
        int countBytesRead;
        // read the incoming bytes until a newline character:
        countBytesRead = Serial.readBytesUntil('\n', buf, num);
        buf[countBytesRead] = '\0';
        return buf;
    } else {
        return NULL;
    }
}

#ifndef NDEBUG

uint8_t dbgCONFIGUREME = 0;
uint8_t dbgNET = 0;
uint8_t dbgTARGET_CRYPTO = 0;
uint8_t dbgTARGET_NVRAM = 0;
uint8_t dbgTARGET_UTIL = 0;

int _AJ_DbgEnabled(const char* module)
{
    return FALSE;
}

#endif
