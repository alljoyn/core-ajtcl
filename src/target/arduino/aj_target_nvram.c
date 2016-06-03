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

#include <ajtcl/aj_nvram.h>
#include <aj_target_nvram.h>

extern void AJ_NVRAM_Layout_Print();

uint8_t emulatedBlock1[SENTINEL_OFFSET];
uint8_t emulatedBlock2[AJ_NVRAM_SIZE_CREDS];
uint8_t emulatedBlock3[AJ_NVRAM_SIZE_SERVICES];
uint8_t emulatedBlock4[AJ_NVRAM_SIZE_FRAMEWORK];
uint8_t emulatedBlock5[AJ_NVRAM_SIZE_ALLJOYNJS];
uint8_t emulatedBlock6[AJ_NVRAM_SIZE_RESERVED];
uint8_t emulatedBlock7[AJ_NVRAM_SIZE_APPS];

typedef struct _nvEmulatedNvram {
    uint8_t* blockStart;
    const uint32_t blockSize;
    uint8_t isCompact;
} nvEmulatedNvramBlock;

/*
 * nvEmulatedNvramBlock table is indexed by AJ_NVRAM_Block_Id enum values
 */
static nvEmulatedNvramBlock nvEmulatedStorages[] = {
    { emulatedBlock1, SENTINEL_OFFSET, TRUE },
    { emulatedBlock2, AJ_NVRAM_SIZE_CREDS, FALSE },
    { emulatedBlock3, AJ_NVRAM_SIZE_SERVICES, FALSE },
    { emulatedBlock4, AJ_NVRAM_SIZE_FRAMEWORK, FALSE },
    { emulatedBlock5, AJ_NVRAM_SIZE_ALLJOYNJS, FALSE },
    { emulatedBlock6, AJ_NVRAM_SIZE_RESERVED, FALSE },
    { emulatedBlock7, AJ_NVRAM_SIZE_APPS, FALSE }
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
    static uint8_t inited = FALSE;
    if (!inited) {
        inited = TRUE;
        _AJ_NVRAM_Clear();
    }
}

void _AJ_NV_Write(AJ_NVRAM_Block_Id blockId, void* dest, const void* buf, uint16_t size, uint8_t isCompact)
{
    memcpy(dest, buf, size);
    if (!isCompact) {
        nvStorages[blockId].isCompact = FALSE;
    }
}

void _AJ_NV_Move(void* dest, const void* buf, uint16_t size)
{
    memmove(dest, buf, size);
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
    nvStorages[blockId].isCompact = TRUE;
    return AJ_OK;
}
