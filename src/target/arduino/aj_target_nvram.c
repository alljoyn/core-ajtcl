/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
 ******************************************************************************/

#include <ajtcl/aj_nvram.h>
#include <aj_target_nvram.h>

extern void AJ_NVRAM_Layout_Print();

static uint8_t emulatedBlock[AJ_NVRAM_SIZE];

typedef struct _nvEmulatedNvram {
    uint8_t* blockStart;
    const uint32_t blockSize;
    uint8_t isCompact;
} nvEmulatedNvramBlock;

/*
 * Pointer initialized inside AJ_NVRAM_Init() or AJ_NVRAM_Init_NewLayout()
 */
static nvEmulatedNvramBlock* nvStorages = NULL;

uint8_t isOldNVRAMLayout = TRUE;

static void _AJ_NVRAM_Init(uint8_t index, uint8_t size)
{
    for (; index < size; ++index) {
        if (*((uint32_t*)nvStorages[index].blockStart) != AJ_NV_SENTINEL) {
            _AJ_NVRAM_Clear(index);
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
            { emulatedBlock, AJ_NVRAM_SIZE, FALSE }
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
            { 0, 0, 0 },
            { emulatedBlock, AJ_NVRAM_SIZE_CREDS, FALSE },
            { emulatedBlock + AJ_NVRAM_SIZE_CREDS, AJ_NVRAM_SIZE_SERVICES, FALSE },
            { emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES, AJ_NVRAM_SIZE_FRAMEWORK, FALSE },
            { emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK, AJ_NVRAM_SIZE_ALLJOYNJS, FALSE },
            { emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK + AJ_NVRAM_SIZE_ALLJOYNJS, AJ_NVRAM_SIZE_RESERVED, FALSE },
            { emulatedBlock + AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK + AJ_NVRAM_SIZE_ALLJOYNJS + AJ_NVRAM_SIZE_RESERVED, AJ_NVRAM_SIZE_APPS, FALSE }
        };
        uint32_t blocksSize = AJ_NVRAM_SIZE_CREDS + AJ_NVRAM_SIZE_SERVICES + AJ_NVRAM_SIZE_FRAMEWORK + AJ_NVRAM_SIZE_ALLJOYNJS +
                              AJ_NVRAM_SIZE_RESERVED + AJ_NVRAM_SIZE_APPS;
        uint8_t size = sizeof(nvNewEmulatedStorages) / sizeof(nvNewEmulatedStorages[0]);
        uint8_t index;

        if (blocksSize > AJ_NVRAM_SIZE) {
            AJ_ErrPrintf(("AJ_NVRAM_Init_NewLayout(): total size of NVRAM blocks exceeds whole NVRAM size\n"));
            return AJ_ERR_FAILURE;
        }
        nvStorages = nvNewEmulatedStorages;
        isOldNVRAMLayout = FALSE;

        for (index = 1; index < size; ++index) {
            if (nvStorages[index].blockSize <= SENTINEL_OFFSET) {
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
}

void _AJ_NV_Move(void* dest, const void* buf, uint16_t size)
{
    memmove(dest, buf, size);
}

void _AJ_NV_Read(void* src, void* buf, uint16_t size)
{
    memcpy(buf, src, size);
}

static void _AJ_NV_Clear(uint8_t index)
{
    memset(nvStorages[index].blockStart, INVALID_DATA_BYTE, nvStorages[index].blockSize);
    *((uint32_t*)(nvStorages[index].blockStart)) = AJ_NV_SENTINEL;
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

void _AJ_NVRAM_ResetLayout()
{
    nvStorages = NULL;
}

