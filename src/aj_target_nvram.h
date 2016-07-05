#ifndef _AJ_TARGET_NVRAM_H_
#define _AJ_TARGET_NVRAM_H_

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
#include <ajtcl/alljoyn.h>

/*
 * Identifies an AJ NVRAM block
 */
#define AJ_NV_SENTINEL ('A' | ('J' << 8) | ('N' << 16) | ('V' << 24))
#define INVALID_ID (0)
#define INVALID_DATA (0xFFFF)
#define INVALID_DATA_BYTE (0xFF)
#define SENTINEL_OFFSET (4)

typedef struct _NV_EntryHeader {
    uint16_t id;           /**< The unique id */
    uint16_t capacity;     /**< The data set size */
} NV_EntryHeader;

#define ENTRY_HEADER_SIZE (sizeof(NV_EntryHeader))

/**
 * Write a block of data to NVRAM
 *
 * @param blockId  A unique id of NVRAM memory block
 * @param dest  Pointer to location of NVRAM
 * @param buf   Pointer to data to be written
 * @param size  The number of bytes to be written
 * @param isCompact Boolean value set to FALSE in case operation causes defragmentation (delete)
 */
void _AJ_NV_Write(AJ_NVRAM_Block_Id blockId, void* dest, const void* buf, uint16_t size, uint8_t isCompact);

/**
 * Read a block of data from NVRAM
 *
 * @param src   Pointer to location of NVRAM
 * @param buf   Pointer to data to be written
 * @param size  The number of bytes to be written
 */
void _AJ_NV_Read(void* src, void* buf, uint16_t size);

/**
 * Erase the whole NVRAM sector and write the sentinel data
 *
 * @param blockId  A unique id of NVRAM memory block
 */
void _AJ_NVRAM_Clear(AJ_NVRAM_Block_Id blockId);

/**
 * Load NVRAM data from a file
 */
AJ_Status _AJ_LoadNVFromFile();

/**
 * Write NVRAM data to a file for persistent storage
 *
 * @param blockId  A unique id of NVRAM memory block
 */
AJ_Status _AJ_StoreNVToFile(AJ_NVRAM_Block_Id blockId);

/**
 * Get NVRAM memory block informations: begin address, end address, block size
 *
 * @param blockId  A unique id of NVRAM memory block
 */
uint8_t* _AJ_GetNVBlockBase(AJ_NVRAM_Block_Id blockId);
uint8_t* _AJ_GetNVBlockEnd(AJ_NVRAM_Block_Id blockId);
uint32_t _AJ_GetNVBlockSize(AJ_NVRAM_Block_Id blockId);

#endif
 
