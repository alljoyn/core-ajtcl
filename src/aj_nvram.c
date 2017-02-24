/**
 * @file
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
 *    
 *    SPDX-License-Identifier: Apache-2.0
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *    
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *    
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
******************************************************************************/

#include "aj_nvram.h"
#include "aj_target_nvram.h"

extern uint8_t* AJ_NVRAM_BASE_ADDRESS;

#define AJ_NVRAM_END_ADDRESS (AJ_NVRAM_BASE_ADDRESS + AJ_NVRAM_SIZE)

void AJ_NVRAM_Layout_Print()
{
    int i = 0;
    uint16_t* data = (uint16_t*)(AJ_NVRAM_BASE_ADDRESS + SENTINEL_OFFSET);
    uint16_t entryId = 0;
    uint16_t capacity = 0;
    AJ_Printf("============ AJ NVRAM Map ===========\n");
    for (i = 0; i < SENTINEL_OFFSET; i++) {
        AJ_Printf("%c", *((uint8_t*)(AJ_NVRAM_BASE_ADDRESS + i)));
    }
    AJ_Printf("\n");

    while ((uint8_t*)data < (uint8_t*)AJ_NVRAM_END_ADDRESS && *data != INVALID_DATA) {
        entryId = *data;
        capacity = *(data + 1);
        AJ_Printf("ID = %d, capacity = %d\n", entryId, capacity);
        data += (ENTRY_HEADER_SIZE + capacity) >> 1;
    }
    AJ_Printf("============ End ===========\n");
}

/**
 * Find an entry in the NVRAM with the specific id
 *
 * @return Pointer pointing to an entry in the NVRAM if an entry with the specified id is found
 *         NULL otherwise
 */
uint8_t* AJ_FindNVEntry(uint16_t id) {
    uint16_t capacity = 0;
    uint16_t* data = (uint16_t*)(AJ_NVRAM_BASE_ADDRESS + SENTINEL_OFFSET);
    while ((uint8_t*)data < (uint8_t*)AJ_NVRAM_END_ADDRESS) {
        if (*data != id) {
            capacity = *(data + 1);
            if (*data == INVALID_DATA) {
                break;
            }
            data += (ENTRY_HEADER_SIZE + capacity) >> 1;
        } else {
            return (uint8_t*)data;
        }
    }
    return NULL;
}

extern AJ_Status _AJ_CompactNVStorage();

AJ_Status AJ_NVRAM_Create(uint16_t id, uint16_t capacity)
{
    uint8_t* ptr;
    NV_EntryHeader header;
    if (!capacity || AJ_NVRAM_Exist(id)) {
        AJ_Printf("AJ_NVRAM_Create: Data set (id = %d) already exits or invalid capacity (%d).\n", id, capacity);
        return AJ_ERR_FAILURE;
    }

    capacity = WORD_ALIGN(capacity); // 4-byte alignment
    ptr = AJ_FindNVEntry(INVALID_DATA);
    if (!ptr || (ptr + ENTRY_HEADER_SIZE + capacity > AJ_NVRAM_END_ADDRESS)) {
        AJ_Printf("Do NVRAM storage compaction.\n");
        _AJ_CompactNVStorage();
        ptr = AJ_FindNVEntry(INVALID_DATA);
        if (!ptr || ptr + ENTRY_HEADER_SIZE + capacity > AJ_NVRAM_END_ADDRESS) {
            AJ_Printf("Error: Do not have enough NVRAM storage space.\n");
            return AJ_ERR_FAILURE;
        }
    }
    header.id = id;
    header.capacity = capacity;
    _AJ_NV_Write(ptr, &header, ENTRY_HEADER_SIZE);
    return AJ_OK;
}

AJ_Status AJ_NVRAM_Delete(uint16_t id)
{
    NV_EntryHeader newHeader;
    uint8_t* ptr = AJ_FindNVEntry(id);
    if (!ptr) {
        return AJ_ERR_FAILURE;
    }

    memcpy(&newHeader, ptr, ENTRY_HEADER_SIZE);
    newHeader.id = 0;
    _AJ_NV_Write(ptr, &newHeader, ENTRY_HEADER_SIZE);
    return AJ_OK;
}

AJ_NV_DATASET* AJ_NVRAM_Open(uint16_t id, char* mode, uint16_t capacity)
{
    AJ_Status status = AJ_OK;
    uint8_t* entry = NULL;
    AJ_NV_DATASET* handle = NULL;

    if (!id) {
        AJ_Printf("Error: A valid id must not be 0.\n");
        goto OPEN_ERR_EXIT;
    }
    if (!mode || mode[1] || (*mode != 'r') && (*mode != 'w')) {
        AJ_Printf("Error: Access mode must be \"r\" or \"w\"\n");
        goto OPEN_ERR_EXIT;
    }
    if (*mode == AJ_NV_DATASET_MODE_WRITE) {
        if (capacity == 0) {
            AJ_Printf("The capacity should not be 0.\n");
            goto OPEN_ERR_EXIT;
        }

        if (AJ_NVRAM_Exist(id)) {
            status = AJ_NVRAM_Delete(id);
        }
        if (status != AJ_OK) {
            goto OPEN_ERR_EXIT;
        }

        status = AJ_NVRAM_Create(id, capacity);
        if (status != AJ_OK) {
            goto OPEN_ERR_EXIT;
        }
        entry = AJ_FindNVEntry(id);
        if (!entry) {
            goto OPEN_ERR_EXIT;
        }
    } else {
        entry = AJ_FindNVEntry(id);
        if (!entry) {
            AJ_Printf("Error: the data set (id = %d) doesn't exist\n", id);
            goto OPEN_ERR_EXIT;
        }
    }

    handle = (AJ_NV_DATASET*)AJ_Malloc(sizeof(AJ_NV_DATASET));
    if (!handle) {
        AJ_Printf("AJ_NVRAM_Open() error: OutOfMemory. \n");
        goto OPEN_ERR_EXIT;
    }

    handle->id = id;
    handle->curPos = 0;
    handle->mode = *mode;
    handle->capacity = ((NV_EntryHeader*)entry)->capacity;
    handle->inode = entry;
    return handle;

OPEN_ERR_EXIT:
    if (handle) {
        AJ_Free(handle);
        handle = NULL;
    }
    AJ_Printf("AJ_NVRAM_Open() fails: status = %d. \n", status);
    return NULL;
}

size_t AJ_NVRAM_Write(void* ptr, uint16_t size, AJ_NV_DATASET* handle)
{
    uint16_t bytesWrite = 0;
    uint8_t patchBytes = 0;
    uint8_t* buf = (uint8_t*)ptr;
    NV_EntryHeader* header = (NV_EntryHeader*)handle->inode;

    if (!handle || handle->mode == AJ_NV_DATASET_MODE_READ) {
        AJ_Printf("AJ_NVRAM_Write() error: The access mode does not allow write.\n");
        return -1;
    }
    if (header->capacity <= handle->curPos) {
        AJ_Printf("AJ_NVRAM_Write() error: No more space for write.\n");
        return -1;
    }

    bytesWrite = header->capacity - handle->curPos;
    bytesWrite = (bytesWrite < size) ? bytesWrite : size;
    if (bytesWrite > 0 && ((handle->curPos & 0x3) != 0)) {
        uint8_t tmpBuf[4];
        uint16_t alignedPos = handle->curPos & (~0x3);
        patchBytes = 4 - (handle->curPos & 0x3);
        memcpy(tmpBuf, handle->inode + sizeof(NV_EntryHeader) + alignedPos, handle->curPos & 0x3);
        memcpy(tmpBuf + (handle->curPos & 0x3), buf, patchBytes);
        _AJ_NV_Write(handle->inode + sizeof(NV_EntryHeader) + alignedPos, tmpBuf, 4);
        buf += patchBytes;
        bytesWrite -= patchBytes;
        handle->curPos += patchBytes;
    }

    if (bytesWrite > 0) {
        _AJ_NV_Write(handle->inode + sizeof(NV_EntryHeader) + handle->curPos, buf, bytesWrite);
        handle->curPos += bytesWrite;
    }
    return bytesWrite + patchBytes;
}

size_t AJ_NVRAM_Read(void* ptr, uint16_t size, AJ_NV_DATASET* handle)
{
    uint16_t bytesRead = 0;
    NV_EntryHeader* header = (NV_EntryHeader*)handle->inode;
    if (!handle || handle->mode == AJ_NV_DATASET_MODE_WRITE) {
        AJ_Printf("AJ_NVRAM_Read() error: The access mode does not allow read.\n");
        return -1;
    }

    if (header->capacity <= handle->curPos) {
        AJ_Printf("AJ_NVRAM_Read() error: No more space for read.\n");
        return -1;
    }
    bytesRead = header->capacity -  handle->curPos;
    bytesRead = (bytesRead < size) ? bytesRead : size;
    if (bytesRead > 0) {
        _AJ_NV_Read(handle->inode + sizeof(NV_EntryHeader) +  handle->curPos, ptr, bytesRead);
        handle->curPos += bytesRead;
    }
    return bytesRead;
}

AJ_Status AJ_NVRAM_Close(AJ_NV_DATASET* handle)
{
    if (!handle) {
        AJ_Printf("AJ_NVRAM_Close() error: Invalid handle. \n");
        return AJ_ERR_INVALID;
    }

    AJ_Free(handle);
    handle = NULL;
    return AJ_OK;
}

uint8_t AJ_NVRAM_Exist(uint16_t id)
{
    if (!id) {
        return FALSE; // the unique id is not allowed to be 0
    }
    return (NULL != AJ_FindNVEntry(id));
}