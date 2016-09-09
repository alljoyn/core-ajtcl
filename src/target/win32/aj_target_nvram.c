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

static uint8_t emulatedBlock[AJ_NVRAM_SIZE];

typedef struct _nvEmulatedNvram {
    const char* nvFile;
    uint8_t* blockStart;
    uint32_t blockSize;
    uint8_t isCompact;
} nvEmulatedNvramBlock;

/*
 * Pointer initialized inside AJ_NVRAM_Init() or AJ_NVRAM_Init_NewLayout()
 */
static nvEmulatedNvramBlock* nvStorages = NULL;

uint8_t isOldNVRAMLayout = TRUE;

static void _AJ_NVRAM_Init(uint8_t idx, uint8_t size)
{
    for (; idx < size; ++idx) {
        _AJ_LoadNVFromFile(idx);
        if (*((uint32_t*)nvStorages[idx].blockStart) != AJ_NV_SENTINEL) {
            _AJ_NVRAM_Clear(idx);
        }
    }
}

void AJ_NVRAM_Init()
{
    if (nvStorages != NULL) {
        AJ_ErrPrintf(("AJ_NVRAM_Init(): NVRAM already initialized\n"));
        return;
    } else {
        /*
         * This is to glue new implementation with old NVRAM layout stored in 1 file
         */
        static nvEmulatedNvramBlock nvOldEmulatedStorage[] = {
            { "ajtcl.nvram", emulatedBlock, AJ_NVRAM_SIZE, FALSE }
        };
        nvStorages = nvOldEmulatedStorage;
        isOldNVRAMLayout = TRUE;
        _AJ_NVRAM_Init(0, 1);
    }
}

AJ_Status AJ_NVRAM_Init_NewLayout()
{
    if (nvStorages != NULL) {
        if (isOldNVRAMLayout) {
            AJ_ErrPrintf(("AJ_NVRAM_Init_NewLayout(): NVRAM already initialized by AJ_NVRAM_Init()\n"));
            return AJ_ERR_INVALID;
        } else {
            AJ_ErrPrintf(("AJ_NVRAM_Init_NewLayout(): NVRAM already initialized by AJ_NVRAM_Init_NewLayout()\n"));
            return AJ_ERR_UNEXPECTED;
        }
    } else {
        /*
         * nvNewEmulatedStorages table is indexed by AJ_NVRAM_Block_Id enum values and is used with new NVRAM file system layout
         */
        static nvEmulatedNvramBlock nvNewEmulatedStorages[] = {
            { 0, 0, 0, 0 },
            { "ajtcl_creds.nvram", emulatedBlock, AJ_NVRAM_SIZE_CREDS, FALSE },
            { "ajtcl_services.nvram", emulatedBlock + AJ_NVRAM_SIZE_CREDS, AJ_NVRAM_SIZE_SERVICES, FALSE },
            { "ajtcl_framework.nvram", emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES, AJ_NVRAM_SIZE_FRAMEWORK, FALSE },
            { "ajtcl_ajjs.nvram", emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK, AJ_NVRAM_SIZE_ALLJOYNJS, FALSE },
            { "ajtcl_reserved.nvram", emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK + AJ_NVRAM_SIZE_ALLJOYNJS, AJ_NVRAM_SIZE_RESERVED, FALSE },
            { "ajtcl_apps.nvram", emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK + AJ_NVRAM_SIZE_ALLJOYNJS + AJ_NVRAM_SIZE_RESERVED, AJ_NVRAM_SIZE_APPS, FALSE }
        };
        uint32_t blocksSize = AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK + AJ_NVRAM_SIZE_ALLJOYNJS +
                              AJ_NVRAM_SIZE_RESERVED + AJ_NVRAM_SIZE_APPS;
        uint8_t size = sizeof(nvNewEmulatedStorages) / sizeof(nvNewEmulatedStorages[0]);
        uint8_t idx;

        if (blocksSize > AJ_NVRAM_SIZE) {
            AJ_ErrPrintf(("AJ_NVRAM_Init_NewLayout(): total size of NVRAM blocks exceeds whole NVRAM size\n"));
            return AJ_ERR_FAILURE;
        }
        nvStorages = nvNewEmulatedStorages;
        isOldNVRAMLayout = FALSE;

        for (idx = 1; idx < size; ++idx) {
            if (nvStorages[idx].blockSize <= SENTINEL_OFFSET) {
                AJ_ErrPrintf(("AJ_NVRAM_Init_NewLayout(): specified NVRAM block size is too small\n"));
                nvStorages = NULL;
                return AJ_ERR_FAILURE;
            }
        }
        _AJ_NVRAM_Init(1, size);
        return AJ_OK;
    }
}

uint8_t* _AJ_GetNVBlockBase(AJ_NVRAM_Block_Id blockId)
{
    return nvStorages[isOldNVRAMLayout ? 0 : blockId].blockStart;
}

uint8_t* _AJ_GetNVBlockEnd(AJ_NVRAM_Block_Id blockId)
{
    return nvStorages[isOldNVRAMLayout ? 0 : blockId].blockStart + nvStorages[isOldNVRAMLayout ? 0 : blockId].blockSize;
}

uint32_t _AJ_GetNVBlockSize(AJ_NVRAM_Block_Id blockId)
{
    return nvStorages[isOldNVRAMLayout ? 0 : blockId].blockSize;
}

void _AJ_NV_Write(AJ_NVRAM_Block_Id blockId, void* dest, const void* buf, uint16_t size, uint8_t isCompact)
{
    memcpy(dest, buf, size);
    if (!isCompact) {
        nvStorages[blockId].isCompact = FALSE;
    }
#ifndef NDEBUG
    AJ_Status status =
#endif
    _AJ_StoreNVToFile(blockId);
    AJ_ASSERT(AJ_OK == status);
}

void _AJ_NV_Move(AJ_NVRAM_Block_Id blockId, void* dest, const void* buf, uint16_t size)
{
    memmove(dest, buf, size);
#ifndef NDEBUG
    AJ_Status status =
#endif
    _AJ_StoreNVToFile(blockId);
    AJ_ASSERT(AJ_OK == status);
}

void _AJ_NV_Read(void* src, void* buf, uint16_t size)
{
    memcpy(buf, src, size);
}

static void _AJ_NV_Clear(uint8_t idx)
{
    memset(nvStorages[idx].blockStart, INVALID_DATA_BYTE, nvStorages[idx].blockSize);
    *((uint32_t*)(nvStorages[idx].blockStart)) = AJ_NV_SENTINEL;
#ifndef NDEBUG
    AJ_Status status =
#endif
    _AJ_StoreNVToFile(idx);
    AJ_ASSERT(AJ_OK == status);
}

void _AJ_NVRAM_Clear(AJ_NVRAM_Block_Id blockId)
{
    if ((blockId == AJ_NVRAM_ID_ALL_BLOCKS) && !isOldNVRAMLayout) {
        AJ_NVRAM_Block_Id _blockId;
        for (_blockId = blockId + 1; _blockId < AJ_NVRAM_ID_END_SENTINEL; ++_blockId) {
            _AJ_NV_Clear(_blockId);
        }
    } else {
        _AJ_NV_Clear(blockId);
    }
}

AJ_Status _AJ_LoadNVFromFile(AJ_NVRAM_Block_Id blockId)
{
    AJ_Status status = AJ_OK;
    FILE* f;
    size_t readCount;
    f = fopen(nvStorages[blockId].nvFile, "rb");
    if (f == NULL) {
        status = AJ_ERR_FAILURE;
        goto Exit;
    }
    memset(nvStorages[blockId].blockStart, INVALID_DATA_BYTE, nvStorages[blockId].blockSize);
    readCount = fread(nvStorages[blockId].blockStart, nvStorages[blockId].blockSize, 1, f);
    if (readCount != 1) {
        status = AJ_ERR_FAILURE;
    }
    fclose(f);

Exit:
    if (status != AJ_OK) {
        AJ_WarnPrintf(("_AJ_LoadNVFromFile(): LoadNVFromFile(\"%s\") failed. status=AJ_ERR_FAILURE\n", nvStorages[blockId].nvFile));
    }
    return status;
}

AJ_Status _AJ_StoreNVToFile(AJ_NVRAM_Block_Id blockId)
{
    AJ_Status status = AJ_OK;
    FILE* f;
    size_t writeCount;
    f = fopen(nvStorages[blockId].nvFile, "wb");
    if (!f) {
        status = AJ_ERR_FAILURE;
        goto Exit;
    }
    writeCount = fwrite(nvStorages[blockId].blockStart, nvStorages[blockId].blockSize, 1, f);
    if (writeCount != 1) {
        status = AJ_ERR_FAILURE;
    }
    fclose(f);

Exit:
    if (status != AJ_OK) {
        AJ_ErrPrintf(("_AJ_StoreNVToFile(): StoreNVToFile(\"%s\") failed. status=AJ_ERR_FAILURE\n", nvStorages[blockId].nvFile));
    }
    return status;
}

// Compact the storage by removing invalid entries
AJ_Status _AJ_CompactNVStorage(AJ_NVRAM_Block_Id blockId)
{
    uint16_t capacity = 0;
    uint16_t id = 0;
    uint16_t* data = (uint16_t*)(nvStorages[blockId].blockStart + SENTINEL_OFFSET);
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

void _AJ_NVRAM_ResetLayout()
{
    nvStorages = NULL;
}