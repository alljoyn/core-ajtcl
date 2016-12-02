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

#include "aj_nvram.h"
#include "aj_target_nvram.h"

uint8_t AJ_EMULATED_NVRAM[AJ_NVRAM_SIZE];
uint8_t* AJ_NVRAM_BASE_ADDRESS;

extern void AJ_NVRAM_Layout_Print();

void AJ_NVRAM_Init()
{
    AJ_NVRAM_BASE_ADDRESS = AJ_EMULATED_NVRAM;
    static uint8_t inited = FALSE;
    if (!inited) {
        inited = TRUE;
        _AJ_NVRAM_Clear();
    }
}

void _AJ_NV_Write(void* dest, const void* buf, uint16_t size)
{
    memcpy(dest, buf, size);
}

void _AJ_NV_Read(void* src, void* buf, uint16_t size)
{
    memcpy(buf, src, size);
}

void _AJ_NVRAM_Clear()
{
    memset((uint8_t*)AJ_NVRAM_BASE_ADDRESS, INVALID_DATA_BYTE, AJ_NVRAM_SIZE);
    *((uint32_t*)AJ_NVRAM_BASE_ADDRESS) = AJ_NV_SENTINEL;
}

// Compact the storage by removing invalid entries
AJ_Status _AJ_CompactNVStorage()
{
    uint16_t capacity = 0;
    uint16_t id = 0;
    uint16_t* data = (uint16_t*)(AJ_NVRAM_BASE_ADDRESS + SENTINEL_OFFSET);
    uint8_t* writePtr = (uint8_t*)data;
    uint16_t entrySize = 0;
    uint16_t garbage = 0;
    //AJ_NVRAM_Layout_Print();
    while ((uint8_t*)data < (uint8_t*)AJ_NVRAM_END_ADDRESS && *data != INVALID_DATA) {
        id = *data;
        capacity = *(data + 1);
        entrySize = ENTRY_HEADER_SIZE + capacity;
        if (id != INVALID_ID) {
            _AJ_NV_Write(writePtr, data, entrySize);
            writePtr += entrySize;
        } else {
            garbage += entrySize;
        }
        data += entrySize >> 1;
    }

    memset(writePtr, INVALID_DATA_BYTE, garbage);
    //AJ_NVRAM_Layout_Print();
    return AJ_OK;
}