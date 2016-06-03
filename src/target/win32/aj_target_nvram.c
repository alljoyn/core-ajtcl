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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE TARGET_NVRAM

#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_debug.h>
#include "../../aj_target_nvram.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgTARGET_NVRAM = 0;
#endif

extern void AJ_NVRAM_Layout_Print();

uint8_t emulatedBlock1[SENTINEL_OFFSET];
uint8_t emulatedBlock2[AJ_NVRAM_SIZE_CREDS];
uint8_t emulatedBlock3[AJ_NVRAM_SIZE_SERVICES];
uint8_t emulatedBlock4[AJ_NVRAM_SIZE_FRAMEWORK];
uint8_t emulatedBlock5[AJ_NVRAM_SIZE_ALLJOYNJS];
uint8_t emulatedBlock6[AJ_NVRAM_SIZE_RESERVED];
uint8_t emulatedBlock7[AJ_NVRAM_SIZE_APPS];

typedef struct _nvEmulatedNvram {
    const char* nvFile;
    uint8_t* blockStart;
    uint32_t blockSize;
    uint8_t isCompact;
} nvEmulatedNvramBlock;

/*
 * nvEmulatedNvramBlock table is indexed by AJ_NVRAM_Block_Id enum values
 */
static nvEmulatedNvramBlock nvEmulatedStorages[] = {
    { "ajtcl_sentinel.nvram", emulatedBlock1, SENTINEL_OFFSET, TRUE },
    { "ajtcl_creds.nvram", emulatedBlock2, AJ_NVRAM_SIZE_CREDS, FALSE },
    { "ajtcl_services.nvram", emulatedBlock3, AJ_NVRAM_SIZE_SERVICES, FALSE },
    { "ajtcl_framework.nvram", emulatedBlock4, AJ_NVRAM_SIZE_FRAMEWORK, FALSE },
    { "ajtcl_ajjs.nvram", emulatedBlock5, AJ_NVRAM_SIZE_ALLJOYNJS, FALSE },
    { "ajtcl_reserved.nvram", emulatedBlock6, AJ_NVRAM_SIZE_RESERVED, FALSE },
    { "ajtcl_apps.nvram", emulatedBlock7, AJ_NVRAM_SIZE_APPS, FALSE }
};

nvEmulatedNvramBlock* nvStorages;

uint8_t* _AJ_GetNVBlockBase(AJ_NVRAM_Block_Id blockId)
{
    return nvStorages[blockId].blockStart;
}

uint8_t* _AJ_GetNVBlockEnd(AJ_NVRAM_Block_Id blockId)
{
    return nvStorages[blockId].blockStart + nvStorages[blockId].blockSize;
}

uint32_t _AJ_GetNVBlockSize(AJ_NVRAM_Block_Id blockId)
{
    return nvStorages[blockId].blockSize;
}

void AJ_NVRAM_Init()
{
    nvStorages = nvEmulatedStorages;
    _AJ_LoadNVFromFile();
    if (*((uint32_t*)nvStorages[0].blockStart) != AJ_NV_SENTINEL) {
        AJ_NVRAM_Clear(AJ_NVRAM_ID_ALL_BLOCKS);
    }
}

void _AJ_NV_Write(AJ_NVRAM_Block_Id blockId, void* dest, const void* buf, uint16_t size, uint8_t isCompact)
{
    memcpy(dest, buf, size);
    if (!isCompact) {
        nvStorages[blockId].isCompact = FALSE;
    }
    _AJ_StoreNVToFile(blockId);
}

void _AJ_NV_Move(AJ_NVRAM_Block_Id blockId, void* dest, const void* buf, uint16_t size)
{
    memmove(dest, buf, size);
    _AJ_StoreNVToFile(blockId);
}

void _AJ_NV_Read(void* src, void* buf, uint16_t size)
{
    memcpy(buf, src, size);
}

void _AJ_NVRAM_Clear(AJ_NVRAM_Block_Id blockId)
{
    if (blockId == AJ_NVRAM_ID_ALL_BLOCKS) {
        uint8_t _blockId = blockId;
        *((uint32_t*)(nvStorages[_blockId].blockStart)) = AJ_NV_SENTINEL;
        for (++_blockId; _blockId < AJ_NVRAM_ID_END_SENTINEL; ++_blockId) {
            memset((uint8_t*)(nvStorages[_blockId].blockStart), INVALID_DATA_BYTE, nvStorages[_blockId].blockSize);
        }
    } else {
        memset((uint8_t*)(nvStorages[blockId].blockStart), INVALID_DATA_BYTE, nvStorages[blockId].blockSize);
    }
    _AJ_StoreNVToFile(blockId);
}

AJ_Status _AJ_LoadNVFromFile()
{
    FILE* f;
    uint8_t i;
    for (i = AJ_NVRAM_ID_ALL_BLOCKS; i < AJ_NVRAM_ID_END_SENTINEL; ++i) {
        f = fopen(nvStorages[i].nvFile, "rb");
        if (f == NULL) {
            AJ_ErrPrintf(("_AJ_LoadNVFromFile(): LoadNVFromFile(\"%s\") failed. status=AJ_ERR_FAILURE\n", nvStorages[i].nvFile));
            return AJ_ERR_FAILURE;
        }
        memset(nvStorages[i].blockStart, INVALID_DATA_BYTE, nvStorages[i].blockSize);
        fread(nvStorages[i].blockStart, nvStorages[i].blockSize, 1, f);
        fclose(f);
    }
    return AJ_OK;
}

AJ_Status _AJ_StoreNVToFile(AJ_NVRAM_Block_Id blockId)
{
    FILE* f;
    if (blockId == AJ_NVRAM_ID_ALL_BLOCKS) {
        for (; blockId < AJ_NVRAM_ID_END_SENTINEL; ++blockId) {
            f = fopen(nvStorages[blockId].nvFile, "wb");
            if (!f) {
                AJ_ErrPrintf(("_AJ_StoreNVToFile(): StoreNVToFile(\"%s\") failed. status=AJ_ERR_FAILURE\n", nvStorages[blockId].nvFile));
                return AJ_ERR_FAILURE;
            }
            fwrite(nvStorages[blockId].blockStart, nvStorages[blockId].blockSize, 1, f);
            fclose(f);
        }
    } else {
        f = fopen(nvStorages[blockId].nvFile, "wb");
        if (!f) {
            AJ_ErrPrintf(("_AJ_StoreNVToFile(): StoreNVToFile(\"%s\") failed. status=AJ_ERR_FAILURE\n", nvStorages[blockId].nvFile));
            return AJ_ERR_FAILURE;
        }
        fwrite(nvStorages[blockId].blockStart, nvStorages[blockId].blockSize, 1, f);
        fclose(f);
    }
    return AJ_OK;
}

// Compact the storage by removing invalid entries
AJ_Status _AJ_CompactNVStorage(AJ_NVRAM_Block_Id blockId)
{
    uint16_t capacity = 0;
    uint16_t id = 0;
    uint16_t* data = (uint16_t*)(nvStorages[blockId].blockStart);
    uint8_t* writePtr = (uint8_t*)data;
    uint16_t entrySize = 0;
    uint16_t garbage = 0;
    if (nvStorages[blockId].isCompact) {
        return AJ_OK;
    }
    while ((uint8_t*)data < (nvStorages[blockId].blockStart + nvStorages[blockId].blockSize) && *data != INVALID_DATA) {
        id = *data;
        capacity = *(data + 1);
        entrySize = ENTRY_HEADER_SIZE + capacity;
        if (id != INVALID_ID) {
            _AJ_NV_Move(blockId, writePtr, data, entrySize);
            writePtr += entrySize;
        } else {
            garbage += entrySize;
        }
        data += entrySize >> 1;
    }

    memset(writePtr, INVALID_DATA_BYTE, garbage);
    _AJ_StoreNVToFile(blockId);
    nvStorages[blockId].isCompact = TRUE;
    return AJ_OK;
}
