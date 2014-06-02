/**
 * @file Unmarshaling implementation
 */
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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

#include "aj_target.h"
#include "aj_util.h"
#include "aj_buf.h"
#include <stdarg.h>
#include "aj_debug.h"
#include "aj_wsl_unmarshal.h"
#include "aj_wsl_wmi.h"

#define str(x) # x
#define xstr(x) str(x)

#define PRE  0x10
#define POST 0x00

wsl_scan_item* WMI_UnmarshalScan(void* data)
{
    wsl_scan_item* scan;
    uint8_t* ptr;
    int i;
    ptr = data;
    scan = (wsl_scan_item*)WSL_InitScanItem();
    scan->rssi = *(ptr + 15);
    for (i = 0; i < 6; i++) {         //MAC is bytes 16 through 22
        scan->bssid[i] = *(ptr + 16 + i);
    }
    scan->ssid = (char*)AJ_WSL_Malloc(sizeof(char*) * *(ptr + 37) + 1);
    for (i = 0; i < *(ptr + 37); i++) {
        scan->ssid[i] = *(ptr + 38 + i);
    }
    scan->ssid[*(ptr + 37)] = '\0';
    return scan;
}

int32_t WMI_Unmarshal(void* data, const char* sig, ...)
{
    va_list args;
    uint8_t* ptr;
    va_start(args, sig);
    ptr = data;
    while (*sig) {
        switch (*sig++) {
        case (WMI_ARG_UINT64):
            {
                uint64_t* u64;
                u64 = (uint64_t*)va_arg(args, uint64_t);
                memcpy(u64, ptr, sizeof(uint64_t));
                ptr += 8;
            }
            break;

        case (WMI_ARG_UINT32):
            {
                uint32_t* u32;
                u32 = (uint32_t*)va_arg(args, uint32_t);
                memcpy(u32, ptr, sizeof(uint32_t));
                ptr += 4;
            }
            break;

        case (WMI_ARG_UINT16):
            {
                uint16_t* u16;
                u16 = (uint16_t*)va_arg(args, uint32_t);
                memcpy(u16, ptr, sizeof(uint16_t));
                ptr += 2;
            }
            break;

        case (WMI_ARG_MAC):
            {
                uint8_t* mac;
                mac = (uint8_t*)va_arg(args, uint32_t);
                memcpy(mac, ptr, sizeof(uint8_t) * 6);
                ptr += 6;
            }
            break;

        case (WMI_ARG_IPV4):
            {
                uint8_t* IPv4;
                IPv4 = (uint8_t*)va_arg(args, uint32_t);
                memcpy(IPv4, ptr, sizeof(uint8_t) * 4);
                ptr += 4;
            }
            break;

        case (WMI_ARG_IPV6):
            {
                uint8_t* IPv6;
                IPv6 = (uint8_t*)va_arg(args, uint32_t);
                memcpy(IPv6, ptr, sizeof(uint8_t) * 16);
                ptr += 16;
            }
            break;

        case (WMI_ARG_BYTE):
            {
                uint8_t* u8;
                u8 = (uint8_t*)va_arg(args, uint32_t);
                memcpy(u8, ptr, sizeof(uint8_t));
                ptr += 1;
            }
            break;

        case (WMI_ARG_STRING):
            {
                char** str;
                uint8_t size;
                memcpy(&size, ptr, sizeof(uint8_t));
                ptr++;
                str = (char**)va_arg(args, char*);
                *str = (char*)AJ_WSL_Malloc(sizeof(char) * size + 1);
                memcpy(*str, ptr, sizeof(char) * size + 1);
                (*str)[size] = '\0';
                ptr += size;
            }
            break;
        }
    }
    va_end(args);
    return ptr - (uint8_t*)data;
}



















