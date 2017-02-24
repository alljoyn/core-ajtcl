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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE NVRAM

#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_debug.h>
#ifdef ARDUINO
#include <ajtcl/aj_target_nvram.h>
#else
#include "../aj_target_nvram.h"
#endif

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgNVRAM = 0;
#endif

typedef struct _nvIdToBlockMapping {
    uint16_t minId;
    uint16_t maxId;
    AJ_NVRAM_Block_Id blockId;
} nvIdToBlockMapping;

static nvIdToBlockMapping nvMemoryMap[] = {
    { 0, 0, AJ_NVRAM_ID_ALL_BLOCKS },
    { AJ_NVRAM_ID_CREDS_BEGIN, AJ_NVRAM_ID_CREDS_MAX, AJ_NVRAM_ID_CREDS_BLOCK },
    { AJ_NVRAM_ID_SERVICES_BEGIN, AJ_NVRAM_ID_SERVICES_MAX, AJ_NVRAM_ID_SERVICES_BLOCK },
    { AJ_NVRAM_ID_FRAMEWORK_BEGIN, AJ_NVRAM_ID_FRAMEWORK_MAX, AJ_NVRAM_ID_FRAMEWORK_BLOCK },
    { AJ_NVRAM_ID_ALLJOYNJS_BEGIN, AJ_NVRAM_ID_ALLJOYNJS_MAX, AJ_NVRAM_ID_ALLJOYNJS_BLOCK },
    { AJ_NVRAM_ID_RESERVED_BEGIN, AJ_NVRAM_ID_RESERVED_MAX, AJ_NVRAM_ID_RESERVED_BLOCK },
    { AJ_NVRAM_ID_APPS_BEGIN, AJ_NVRAM_ID_APPS_MAX, AJ_NVRAM_ID_APPS_BLOCK }
};

extern uint8_t isOldNVRAMLayout;

static AJ_NVRAM_Block_Id _AJ_NVRAM_Find_NV_Storage(uint16_t id)
{
    uint8_t idx;
    if (isOldNVRAMLayout) {
        return AJ_NVRAM_ID_ALL_BLOCKS;
    }
    for (idx = 0; idx < sizeof(nvMemoryMap) / sizeof(nvMemoryMap[0]); ++idx) {
        if (id <= nvMemoryMap[idx].maxId) {
            break;
        }
    }
    return ((idx == AJ_NVRAM_ID_END_SENTINEL) ? AJ_NVRAM_ID_END_SENTINEL : nvMemoryMap[idx].blockId);
}

static uint32_t _AJ_GetNVRAMBlockUsedSize(uint8_t* beginAddress, uint8_t* endAddress)
{
    uint32_t size = 0;
    uint16_t* data = (uint16_t*)(beginAddress + SENTINEL_OFFSET);
    uint16_t entryId = 0;
    uint16_t capacity = 0;
    while ((uint8_t*)data < endAddress && *data != INVALID_DATA) {
        entryId = *data;
        capacity = *(data + 1);
        if (entryId != 0) {
            size += capacity + ENTRY_HEADER_SIZE;
        }
        data += (ENTRY_HEADER_SIZE + capacity) >> 1;
    }
    return size + SENTINEL_OFFSET;
}

uint32_t AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_Block_Id blockId)
{
    if ((blockId == AJ_NVRAM_ID_ALL_BLOCKS) && !isOldNVRAMLayout) {
        uint32_t sum = 0;
        AJ_NVRAM_Block_Id _blockId;
        for (_blockId = (AJ_NVRAM_Block_Id)(blockId + 1); _blockId < AJ_NVRAM_ID_END_SENTINEL; _blockId = (AJ_NVRAM_Block_Id)(_blockId + 1)) {
            sum += _AJ_GetNVRAMBlockUsedSize(_AJ_GetNVBlockBase(_blockId), _AJ_GetNVBlockEnd(_blockId));
        }
        return sum;
    } else {
        return _AJ_GetNVRAMBlockUsedSize(_AJ_GetNVBlockBase(blockId), _AJ_GetNVBlockEnd(blockId));
    }
}

uint32_t AJ_NVRAM_GetSize()
{
    return AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS);
}

extern AJ_Status _AJ_CompactNVStorage(AJ_NVRAM_Block_Id blockId);

uint32_t AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_Block_Id blockId)
{
    if ((blockId == AJ_NVRAM_ID_ALL_BLOCKS) && !isOldNVRAMLayout) {
        uint32_t sum = 0;
        AJ_NVRAM_Block_Id _blockId;
        for (_blockId = (AJ_NVRAM_Block_Id)(blockId + 1); _blockId < AJ_NVRAM_ID_END_SENTINEL; _blockId = (AJ_NVRAM_Block_Id)(_blockId + 1)) {
            _AJ_CompactNVStorage(_blockId);
            sum += _AJ_GetNVBlockSize(_blockId);
        }
        sum -= AJ_NVRAM_GetSize_NewLayout(blockId);
        return sum;
    } else {
        _AJ_CompactNVStorage(isOldNVRAMLayout ? AJ_NVRAM_ID_ALL_BLOCKS : blockId);
        return _AJ_GetNVBlockSize(blockId) - AJ_NVRAM_GetSize_NewLayout(blockId);
    }
}

uint32_t AJ_NVRAM_GetSizeRemaining()
{
    return AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS);
}

void AJ_NVRAM_Layout_Print()
{
    AJ_NVRAM_Block_Id blockId;
    uint16_t* data;
    uint16_t entryId = 0;
    uint16_t capacity = 0;
    uint8_t i;

    AJ_AlwaysPrintf(("============ AJ NVRAM Map ===========\n"));

    for (blockId = (AJ_NVRAM_Block_Id)(isOldNVRAMLayout ? AJ_NVRAM_ID_ALL_BLOCKS : AJ_NVRAM_ID_ALL_BLOCKS + 1); blockId < AJ_NVRAM_ID_END_SENTINEL; blockId = (AJ_NVRAM_Block_Id)(blockId + 1)) {
        for (i = 0; i < SENTINEL_OFFSET; i++) {
            AJ_AlwaysPrintf(("%c", *((uint8_t*)(_AJ_GetNVBlockBase(blockId) + i))));
        }
        AJ_AlwaysPrintf(("\n"));
        data = (uint16_t*)(_AJ_GetNVBlockBase(blockId) + SENTINEL_OFFSET);
        while ((uint8_t*)data < _AJ_GetNVBlockEnd(blockId) && *data != INVALID_DATA) {
            entryId = *data;
            capacity = *(data + 1);
            AJ_AlwaysPrintf(("ID = %d, capacity = %d\n", entryId, capacity));
            data += (ENTRY_HEADER_SIZE + capacity) >> 1;
        }
        AJ_AlwaysPrintf(("============ End Block ID = %d ===========\n", blockId));
        if (isOldNVRAMLayout) {
            break;
        }
    }
}

/**
 * Find an entry in the NVRAM with the specific id
 *
 * @return Pointer pointing to an entry in the NVRAM if an entry with the specified id is found
 *         NULL otherwise
 */
uint8_t* AJ_FindNVEntry(AJ_NVRAM_Block_Id blockId, uint16_t id)
{
    uint16_t capacity = 0;
    uint16_t* data = (uint16_t*)(_AJ_GetNVBlockBase(blockId) + SENTINEL_OFFSET);

    AJ_InfoPrintf(("AJ_FindNVEntry(id=%d.)\n", id));

    while ((uint8_t*)data < (uint8_t*)_AJ_GetNVBlockEnd(blockId)) {
        if (*data != id) {
            capacity = *(data + 1);
            if (*data == INVALID_DATA) {
                break;
            }
            data += (ENTRY_HEADER_SIZE + capacity) >> 1;
        } else {
            AJ_InfoPrintf(("AJ_FindNVEntry(): data=0x%p\n", data));
            return (uint8_t*)data;
        }
    }
    AJ_InfoPrintf(("AJ_FindNVEntry(): data=NULL\n"));
    return NULL;
}

AJ_Status AJ_NVRAM_Create(uint16_t id, uint16_t capacity)
{
    uint8_t* ptr;
    NV_EntryHeader header;
    AJ_NVRAM_Block_Id blockId;

    AJ_InfoPrintf(("AJ_NVRAM_Create(id=%d., capacity=%d.)\n", id, capacity));

    if ((id == INVALID_DATA) || !capacity || AJ_NVRAM_Exist(id)) {
        AJ_ErrPrintf(("AJ_NVRAM_Create(): AJ_ERR_FAILURE\n"));
        return AJ_ERR_FAILURE;
    }

    blockId = _AJ_NVRAM_Find_NV_Storage(id);
    capacity = WORD_ALIGN(capacity); // 4-byte alignment
    ptr = AJ_FindNVEntry(blockId, INVALID_DATA);
    if (!ptr || (ptr + ENTRY_HEADER_SIZE + capacity > _AJ_GetNVBlockEnd(blockId))) {
        _AJ_CompactNVStorage(blockId);
        ptr = AJ_FindNVEntry(blockId, INVALID_DATA);
        if (!ptr || ptr + ENTRY_HEADER_SIZE + capacity > _AJ_GetNVBlockEnd(blockId)) {
            AJ_ErrPrintf(("AJ_NVRAM_Create(): AJ_ERR_FAILURE, slot = %d, reason: %s\n", blockId, !ptr ? "no empty slot" : "not enough capacity left in nvram block"));
            return AJ_ERR_FAILURE;
        }
    }
    header.id = id;
    header.capacity = capacity;
    _AJ_NV_Write(blockId, ptr, &header, ENTRY_HEADER_SIZE, TRUE);
    return AJ_OK;
}

AJ_Status AJ_NVRAM_SecureDelete(uint16_t id)
{
    NV_EntryHeader newHeader;
    uint8_t* ptr = NULL;
    uint8_t* buf = NULL;
    AJ_NVRAM_Block_Id blockId;

    AJ_InfoPrintf(("AJ_NVRAM_SecureDelete(id=%d.)\n", id));

    if (id != INVALID_DATA) {
        blockId = _AJ_NVRAM_Find_NV_Storage(id);
        ptr = AJ_FindNVEntry(blockId, id);
    }

    if (!ptr) {
        AJ_ErrPrintf(("AJ_NVRAM_SecureDelete(): AJ_ERR_FAILURE\n"));
        return AJ_ERR_FAILURE;
    }

    memcpy(&newHeader, ptr, ENTRY_HEADER_SIZE);
    newHeader.id = 0;
    _AJ_NV_Write(blockId, ptr, &newHeader, ENTRY_HEADER_SIZE, FALSE);

    buf = (uint8_t*)AJ_Malloc(newHeader.capacity);

    if (!buf) {
        AJ_ErrPrintf(("AJ_NVRAM_SecureDelete(): AJ_ERR_RESOURCES\n"));
        return AJ_ERR_RESOURCES;
    }

    AJ_MemZeroSecure(buf, newHeader.capacity);
    _AJ_NV_Write(blockId, ptr + ENTRY_HEADER_SIZE, buf, sizeof(buf), TRUE);
    AJ_Free(buf);

    return AJ_OK;
}

AJ_Status AJ_NVRAM_Delete(uint16_t id)
{
    NV_EntryHeader newHeader;
    uint8_t* ptr = NULL;
    AJ_NVRAM_Block_Id blockId;

    AJ_InfoPrintf(("AJ_NVRAM_Delete(id=%d.)\n", id));

    if (id != INVALID_DATA) {
        blockId = _AJ_NVRAM_Find_NV_Storage(id);
        ptr = AJ_FindNVEntry(blockId, id);
    }

    if (!ptr) {
        AJ_ErrPrintf(("AJ_NVRAM_Delete(): AJ_ERR_FAILURE\n"));
        return AJ_ERR_FAILURE;
    }

    memcpy(&newHeader, ptr, ENTRY_HEADER_SIZE);
    newHeader.id = 0;
    _AJ_NV_Write(blockId, ptr, &newHeader, ENTRY_HEADER_SIZE, FALSE);

    return AJ_OK;
}

AJ_NV_DATASET* AJ_NVRAM_Open(uint16_t id, const char* mode, uint16_t capacity)
{
    AJ_Status status = AJ_OK;
    uint8_t* entry = NULL;
    AJ_NV_DATASET* handle = NULL;
    AJ_NVRAM_Block_Id blockId;

    AJ_InfoPrintf(("AJ_NVRAM_Open(id=%d., mode=\"%s\", capacity=%d.)\n", id, mode, capacity));

    if (!id || (id == INVALID_DATA)) {
        AJ_ErrPrintf(("AJ_NVRAM_Open(): invalid id\n"));
        goto OPEN_ERR_EXIT;
    }
    if (!mode || mode[1] || (*mode != 'r' && *mode != 'w')) {
        AJ_ErrPrintf(("AJ_NVRAM_Open(): invalid access mode\n"));
        goto OPEN_ERR_EXIT;
    }
    blockId = _AJ_NVRAM_Find_NV_Storage(id);
    if (*mode == AJ_NV_DATASET_MODE_WRITE) {
        if (capacity == 0) {
            AJ_ErrPrintf(("AJ_NVRAM_Open(): invalid capacity\n"));
            goto OPEN_ERR_EXIT;
        }

        if (AJ_NVRAM_Exist(id)) {
            status = AJ_NVRAM_Delete(id);
        }
        if (status != AJ_OK) {
            AJ_ErrPrintf(("AJ_NVRAM_Open(): AJ_NVRAM_Delete() failure: status=%s\n", AJ_StatusText(status)));
            goto OPEN_ERR_EXIT;
        }

        status = AJ_NVRAM_Create(id, capacity);
        if (status != AJ_OK) {
            AJ_ErrPrintf(("AJ_NVRAM_Open(): AJ_NVRAM_Create() failure: status=%s\n", AJ_StatusText(status)));
            goto OPEN_ERR_EXIT;
        }
        entry = AJ_FindNVEntry(blockId, id);
        if (!entry) {
            AJ_ErrPrintf(("AJ_NVRAM_Open(): Data set %d. does not exist\n", id));
            goto OPEN_ERR_EXIT;
        }
    } else {
        entry = AJ_FindNVEntry(blockId, id);
        if (!entry) {
            AJ_WarnPrintf(("AJ_NVRAM_Open(): Data set %d. does not exist\n", id));
            goto OPEN_ERR_EXIT;
        }
    }

    handle = (AJ_NV_DATASET*)AJ_Malloc(sizeof(AJ_NV_DATASET));
    if (!handle) {
        AJ_ErrPrintf(("AJ_NVRAM_Open(): AJ_Malloc() failure\n"));
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
    AJ_ErrPrintf(("AJ_NVRAM_Open(): failure: status=%s\n", AJ_StatusText(status)));
    return NULL;
}

size_t AJ_NVRAM_Write(const void* ptr, uint16_t size, AJ_NV_DATASET* handle)
{
    uint16_t bytesWrite = 0;
    uint8_t patchBytes = 0;
    uint8_t* buf = (uint8_t*)ptr;
    NV_EntryHeader* header;
    AJ_NVRAM_Block_Id blockId;

    if (!handle || (handle->mode == AJ_NV_DATASET_MODE_READ) || (handle->id == INVALID_DATA)) {
        AJ_ErrPrintf(("AJ_NVRAM_Write(): AJ_ERR_ACCESS\n"));
        return -1;
    }

    header = (NV_EntryHeader*)handle->inode;

    AJ_InfoPrintf(("AJ_NVRAM_Write(ptr=0x%p, size=%d., handle=0x%p)\n", ptr, size, handle));

    if (header->capacity <= handle->curPos) {
        AJ_AlwaysPrintf(("AJ_NVRAM_Write(): AJ_ERR_RESOURCES\n"));
        return -1;
    }

    blockId = _AJ_NVRAM_Find_NV_Storage(handle->id);
    bytesWrite = header->capacity - handle->curPos;
    bytesWrite = (bytesWrite < size) ? bytesWrite : size;
    if (bytesWrite > 0 && ((handle->curPos & 0x3) != 0)) {
        uint8_t tmpBuf[4];
        uint16_t alignedPos = handle->curPos & (~0x3);
        memset(tmpBuf, INVALID_DATA_BYTE, sizeof(tmpBuf));
        patchBytes = 4 - (handle->curPos & 0x3);
        memcpy(tmpBuf, handle->inode + sizeof(NV_EntryHeader) + alignedPos, handle->curPos & 0x3);
        if (patchBytes > bytesWrite) {
            patchBytes = (uint8_t)bytesWrite;
        }
        memcpy(tmpBuf + (handle->curPos & 0x3), buf, patchBytes);
        _AJ_NV_Write(blockId, handle->inode + sizeof(NV_EntryHeader) + alignedPos, tmpBuf, 4, TRUE);
        buf += patchBytes;
        bytesWrite -= patchBytes;
        handle->curPos += patchBytes;
    }

    if (bytesWrite > 0) {
        _AJ_NV_Write(blockId, handle->inode + sizeof(NV_EntryHeader) + handle->curPos, buf, bytesWrite, TRUE);
        handle->curPos += bytesWrite;
    }
    return bytesWrite + patchBytes;
}

const void* AJ_NVRAM_Peek(AJ_NV_DATASET* handle)
{
    if (!handle || handle->mode == AJ_NV_DATASET_MODE_WRITE) {
        AJ_ErrPrintf(("AJ_NVRAM_Peek(): AJ_ERR_ACCESS\n"));
        return NULL;
    }
    return (const void*)(handle->inode + sizeof(NV_EntryHeader) +  handle->curPos);
}

size_t AJ_NVRAM_Read(void* ptr, uint16_t size, AJ_NV_DATASET* handle)
{
    uint16_t bytesRead = 0;
    NV_EntryHeader* header;

    if (!handle || handle->mode == AJ_NV_DATASET_MODE_WRITE) {
        AJ_ErrPrintf(("AJ_NVRAM_Read(): AJ_ERR_ACCESS\n"));
        return -1;
    }

    header = (NV_EntryHeader*)handle->inode;

    AJ_InfoPrintf(("AJ_NVRAM_Read(ptr=0x%p, size=%d., handle=0x%p)\n", ptr, size, handle));

    if (header->capacity <= handle->curPos) {
        AJ_ErrPrintf(("AJ_NVRAM_Read(): AJ_ERR_RESOURCES\n"));
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
    AJ_InfoPrintf(("AJ_NVRAM_Close(handle=0x%p)\n", handle));

    if (!handle) {
        AJ_ErrPrintf(("AJ_NVRAM_Close(): AJ_ERR_INVALID\n"));
        return AJ_ERR_INVALID;
    }

    AJ_Free(handle);
    handle = NULL;
    return AJ_OK;
}

uint8_t AJ_NVRAM_Exist(uint16_t id)
{
    AJ_InfoPrintf(("AJ_NVRAM_Exist(id=%d.)\n", id));

    if (!id || (id == INVALID_DATA)) {
        AJ_ErrPrintf(("AJ_NVRAM_Exist(): AJ_ERR_INVALID\n"));
        return FALSE; // the unique id is not allowed to be 0 or 0xffff
    }
    return (NULL != AJ_FindNVEntry(_AJ_NVRAM_Find_NV_Storage(id), id));
}

void AJ_NVRAM_Clear()
{
    _AJ_NVRAM_Clear(AJ_NVRAM_ID_ALL_BLOCKS);
}

void AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_Block_Id blockId)
{
    _AJ_NVRAM_Clear(isOldNVRAMLayout ? AJ_NVRAM_ID_ALL_BLOCKS : blockId);
}