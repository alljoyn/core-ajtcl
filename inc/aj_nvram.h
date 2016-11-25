#ifndef _AJ_NVRAM_H_
#define _AJ_NVRAM_H_

/**
 * @file aj_nvram.h
 * @defgroup aj_nvram Non-Volatile RAM Management
 * @{
 */
/******************************************************************************
 *  * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
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
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_status.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AJ_NVRAM_ID_CREDS_BEGIN      0x0001     /**< First NVRAM ID reserved for AllJoyn credentials management */
#define AJ_NVRAM_ID_CREDS_MAX        0x0FFF     /**< Last NVRAM ID reserved for AllJoyn credentials management */
#define AJ_NVRAM_ID_SERVICES_BEGIN   0x1000     /**< First NVRAM ID reserved for AllJoyn services */
#define AJ_NVRAM_ID_SERVICES_MAX     0x1FFF     /**< Last NVRAM ID reserved for AllJoyn services */
#define AJ_NVRAM_ID_FRAMEWORK_BEGIN  0x2000     /**< First NVRAM ID reserved for AllJoyn framework */
#define AJ_NVRAM_ID_FRAMEWORK_MAX    0x2FFF     /**< Last NVRAM ID reserved for AllJoyn framework */
#define AJ_NVRAM_ID_ALLJOYNJS_BEGIN  0x3000     /**< First NVRAM ID reserved for AllJoyn AllJoyn.js */
#define AJ_NVRAM_ID_ALLJOYNJS_MAX    0x3FFF     /**< Last NVRAM ID reserved for AllJoyn AllJoyn.js */
#define AJ_NVRAM_ID_RESERVED_BEGIN   0x4000     /**< First NVRAM ID reserved for AllJoyn future use*/
#define AJ_NVRAM_ID_RESERVED_MAX     0x7FFF     /**< Last NVRAM ID reserved for AllJoyn future use*/
#define AJ_NVRAM_ID_APPS_BEGIN       0x8000     /**< First NVRAM ID available for application use */
#define AJ_NVRAM_ID_APPS_MAX         0xFFFE     /**< Last NVRAM ID available for application use */

/*
 * Below are enumerated all NVRAM blocks.
 * Each NVRAM entry having ID falling into boundaries defined above
 * belongs exclusively to one dedicated NVRAM block.
 * Mapping of entry_ID:AJ_NVRAM_Block_Id is defined in implementation file (aj_nvram.c) while
 * address space of each block is defined in target implementation file (aj_target_nvram.c).
 */
typedef enum {
    AJ_NVRAM_ID_ALL_BLOCKS      = 0x00,
    AJ_NVRAM_ID_CREDS_BLOCK     = 0x01,
    AJ_NVRAM_ID_SERVICES_BLOCK  = 0x02,
    AJ_NVRAM_ID_FRAMEWORK_BLOCK = 0x03,
    AJ_NVRAM_ID_ALLJOYNJS_BLOCK = 0x04,
    AJ_NVRAM_ID_RESERVED_BLOCK  = 0x05,
    AJ_NVRAM_ID_APPS_BLOCK      = 0x06,
    AJ_NVRAM_ID_END_SENTINEL /* note: this entry must be always the last one */
} AJ_NVRAM_Block_Id;

#define AJ_NV_DATASET_MODE_READ      'r'      /**< Data set is in read mode */
#define AJ_NV_DATASET_MODE_WRITE     'w'      /**< Data set is in write mode */

#ifndef AJ_NVRAM_SIZE
#define AJ_NVRAM_SIZE (4096)
#endif

#ifndef AJ_NVRAM_SIZE_CREDS
#define AJ_NVRAM_SIZE_CREDS (1024)
#endif
#ifndef AJ_NVRAM_SIZE_SERVICES
#define AJ_NVRAM_SIZE_SERVICES (1024)
#endif
#ifndef AJ_NVRAM_SIZE_FRAMEWORK
#define AJ_NVRAM_SIZE_FRAMEWORK (512)
#endif
#ifndef AJ_NVRAM_SIZE_ALLJOYNJS
#define AJ_NVRAM_SIZE_ALLJOYNJS (512)
#endif
#ifndef AJ_NVRAM_SIZE_RESERVED
#define AJ_NVRAM_SIZE_RESERVED (512)
#endif
#ifndef AJ_NVRAM_SIZE_APPS
#define AJ_NVRAM_SIZE_APPS (512)
#endif
/**
 * AllJoyn NVRAM dataset handle. Applications should treat this an opaque data structure. The values
 * of the fields are implementation specific so cannot be relied on to have the same meaning across
 * different implementations.
 */
typedef struct _AJ_NV_DATASET {
    uint8_t mode;          /**< The access mode (read or write) of a data set */
    uint16_t curPos;       /**< The current read/write offset of a data set */
    uint16_t capacity;     /**< The capacity of the data set established by AJ_NVRAM_Open() */
    uint16_t id;           /**< The unique id of a data set */
    uint8_t* inode;        /**< Pointer or offset to a location of the data set in the NVRAM */
    void* internal;        /**< Implementation-specific state */
} AJ_NV_DATASET;

/**
 * Initialize NVRAM
 *
 * @remarks
 *  If AJ_NVRAM_Init_NewLayout() was already called, call to AJ_NVRAM_Init() has no effect.
 */
void AJ_NVRAM_Init();

/**
 * Initialize NVRAM using new layout
 *
 * @remarks
 *  This function must be called before AJ_NVRAM_Init() to use new NVRAM layout.
 *  New layout splits continuous memory into logical segments which makes it more efficient
 *  on targets with file system where each segment maps on a dedicated file.
 *  It's important to note that with this layout there is no total NVRAM capacity when creating
 *  new NVRAM entry but each entry belongs to one segment (see AJ_NVRAM_Block_Id enum) of fixed size.
 *  This implies that even if there plenty of available NVRAM space in total, the segment which
 *  data-to-be-written belongs to may be full so this data cannot be written.
 *
 *  See supporting API calls:
 *  - AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_Block_Id blockId)
 *  - AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_Block_Id blockId)
 *  - AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_Block_Id blockId)
 *
 * @return AJ_OK if init was successfull
 *         AJ_ERR_UNEXPECTED in case NVRAM was already initialized by AJ_NVRAM_Init_NewLayout()
 *         AJ_ERR_INVALID in case NVRAM was already initialized by AJ_NVRAM_Init()
 *         AJ_ERR_FAILURE in case of any other failure.
 */
AJ_Status AJ_NVRAM_Init_NewLayout();

/**
 * Get the number of bytes currently used in the NVRAM memory block
 *
 * @remarks
 *  Should not be used with NVRAM initialized by AJ_NVRAM_Init_NewLayout().
 *  Deprecated due to new AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_Block_Id blockId) call.
 *
 * @return      Number of bytes used
 */
AJ_DEPRECATED_ON(uint32_t AJ_NVRAM_GetSize(), 16.10);

/**
 * Get the number of bytes currently used in the NVRAM memory block
 *
 * @param blockId  A unique id of NVRAM memory block.
 *
 * @remarks
 *  If NVRAM was initialized by AJ_NVRAM_Init() it returns the used size of
 *  whole NVRAM, blockId is ignored, so it works like AJ_NVRAM_GetSize().
 *
 * @return      Number of bytes used
 */
uint32_t AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_Block_Id blockId);

/**
 * Get the number of bytes unallocated in the NVRAM memory block
 *
 * @remarks
 *  Should not be used with NVRAM initialized by AJ_NVRAM_Init_NewLayout().
 *  Deprecated due to new AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_Block_Id blockId) call.
 *
 * @return      Number of free bytes remaining
 */
AJ_DEPRECATED_ON(uint32_t AJ_NVRAM_GetSizeRemaining(), 16.10);

/**
 * Get the number of bytes unallocated in the NVRAM memory block
 *
 * @param blockId  A unique id of NVRAM memory block.
 *
 * @remarks
 *  If NVRAM was initialized by AJ_NVRAM_Init() it returns the free size of
 *  whole NVRAM, blockId is ignored, so it works like AJ_NVRAM_GetSizeRemaining().
 *
 * @return      Number of free bytes remaining
 */
uint32_t AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_Block_Id blockId);

/**
 * Completely clear NVRAM
 *
 * @remarks
 *  Should not be used with NVRAM initialized by AJ_NVRAM_Init_NewLayout().
 *  Deprecated due to new AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_Block_Id blockId) call.
 *
 */
AJ_DEPRECATED_ON(void AJ_NVRAM_Clear(), 16.10);

/**
 * Completely clear NVRAM
 *
 * @param blockId  A unique id of NVRAM memory block.
 *
 * @remarks
 *  If NVRAM was initialized by AJ_NVRAM_Init() clears all NVRAM, blockId is ignored,
 *  so it works like AJ_NVRAM_Clear().
 *
 */
void AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_Block_Id blockId);

/**
 * Open a data set
 *
 * @param id  A unique id for a data set. The value must not be 0.
 * @param mode C string containing a data set access mode. It can be:
 *    "r"  : read: Open data set for input operations. The data set must exist.
 *    "w"  : write: Create an empty data set for output operations. If a data set with the same id already exists, its contents are discarded.
 * @param capacity The reserved space size for the data set. Only used for "w" access mode.
 *
 * @return A handle that specifies the data set. NULL if the open operation fails.
 */
AJ_NV_DATASET* AJ_NVRAM_Open(uint16_t id, const char* mode, uint16_t capacity);

/**
 * Write to the data set specified by a handle
 *
 * @param ptr   Pointer to a block of memory with a size of at least size bytes to be written to NVRAM.
 * @param size  Size, in bytes, to be written.
 * @param handle Pointer to an AJ_NV_DATASET object that specifies a data set.
 *
 * @return The number of byte of data written to the data set or -1 if the write failed.
 */
size_t AJ_NVRAM_Write(const void* ptr, uint16_t size, AJ_NV_DATASET* handle);

/**
 * Read from the data set specified by a handle
 *
 * @param ptr   Pointer to a block of memory with a size of at least size bytes to be read from NVRAM.
 * @param size  Size, in bytes, to be read.
 * @param handle Pointer to an AJ_NV_DATASET object that specifies a data set.
 *
 * @return The number of bytes of data read from the data set, or -1 if the read failed.
 */
size_t AJ_NVRAM_Read(void* ptr, uint16_t size, AJ_NV_DATASET* handle);

/**
 * Returns a pointer to data at the current read position of an NVRAM data set. This function may
 * not be supported by all implementations. If this function returns NULL the caller will have to
 * allocate a buffer and use AJ_NVRAM_Read() to load the data set into memory.
 *
 * Note: the caller cannot assume that the pointer value returned will remain valid after the data
 * set is closed.
 *
 * @param handle Pointer to an AJ_NV_DATASET object that has been opened for reading.
 *
 * @return  A pointer to the requested data or NULL if this function is not supported by the
 *          implementation or the data set was not opened for reading.
 */
const void* AJ_NVRAM_Peek(AJ_NV_DATASET* handle);

/**
 * Close the data set and release the handle
 *
 * @param handle Pointer to an AJ_NV_DATASET object that specifies a data set.
 *
 * @return AJ_ERR_INVALID if the handle is invalid, otherwise AJ_OK.
 */
AJ_Status AJ_NVRAM_Close(AJ_NV_DATASET* handle);

/**
 * Check if a data set with a unique id exists
 *
 * @param id A unique ID for a data set. A valid id must not be 0.
 *
 * @return 1 if a data set with the specified id exists
 *         0 if not.
 */
uint8_t AJ_NVRAM_Exist(uint16_t id);

/**
 * Securely delete (overwrite) a data set specified by the id
 *
 * @param id A unique id for a data set.
 *
 * @return AJ_OK if the data set is deleted successfully
 *         AJ_ERR_FAILURE if the data set does not exist.
 */
AJ_Status AJ_NVRAM_SecureDelete(uint16_t id);

/**
 * Delete a data set specified by the id
 *
 * @param id A unique id for a data set.
 *
 * @return AJ_OK if the data set is deleted successfully
 *         AJ_ERR_FAILURE if the data set does not exist.
 */
AJ_Status AJ_NVRAM_Delete(uint16_t id);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
