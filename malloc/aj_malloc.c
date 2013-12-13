/**
 * @file
 */
/******************************************************************************
 *  *    Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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

#include <stdio.h>
#include <assert.h>

#include "aj_target.h"
#include "aj_util.h"


#define MIN_BLOCK_SIZE 16

typedef struct _MemBlock {
    struct _MemBlock* next;
    uint8_t mem[MIN_BLOCK_SIZE - sizeof(void*)];
} MemBlock;

typedef struct _MemPool {
    const uint16_t size;     /* Size of the pool entries in bytes */
    const uint16_t entries;  /* Number of entries in this pool */
    void* endOfPool;         /* Address of end of this pool */
    MemBlock* freeList;      /* Linked free list for this pool */
} MemPool;

static MemPool memPools[] = {
    { 32,   1,  NULL, NULL },
    { 96,   4,  NULL, NULL },
    { 192,  1,  NULL, NULL }
};

#define HEAP_SIZE 720

static uint32_t heap[HEAP_SIZE / 4];


static void InitPools()
{
#ifndef NDEBUG
    size_t totalSz = 0;
#endif
    size_t i;
    size_t n;
    uint8_t* heapPtr = (uint8_t*)heap;

    for (i = 0; i < ArraySize(memPools); ++i) {
        /*
         * Add all blocks to the pool free list
         */
        for (n = memPools[i].entries; n != 0; --n) {
            MemBlock* block = (MemBlock*)heapPtr;
            block->next = memPools[i].freeList;
            memPools[i].freeList = block;
            heapPtr += memPools[i].size;
#ifndef NDEBUG
            totalSz += memPools[i].size;
            assert(totalSz <= sizeof(heap));
#endif
        }
        /*
         * Save end of pool pointer for use by AJ_Free
         */
        memPools[i].endOfPool = (void*)heapPtr;
    }
}

void* AJ_Malloc(size_t sz)
{
    size_t i;

    /*
     * One time initialization
     */
    if (!memPools[0].endOfPool) {
        InitPools();
    }
    /*
     * Find smallest pool that can satisfy the allocation
     */
    for (i = 0; i < ArraySize(memPools); ++i) {
        if ((sz <= memPools[i].size) && memPools[i].freeList) {
            MemBlock* block = memPools[i].freeList;
            //printf("AJ_Malloc pool %d allocated %d\n", memPools[i].size, sz);
            memPools[i].freeList = block->next;
            return (void*)block;
        }
    }
#ifndef NDEBUG
    printf("AJ_Malloc of %d bytes failed\n", sz);
    for (i = 0; i < ArraySize(memPools); ++i) {
        printf("    Pool %d %s\n", memPools[i].size, memPools[i].freeList ? "available" : "depleted");
    }
#endif
    return NULL;
}

void AJ_Free(void* mem)
{
    size_t i;

    if (mem) {
        assert((ptrdiff_t)mem >= (ptrdiff_t)heap);
        /*
         * Locate the pool from which the released memory was allocated
         */
        for (i = 0; i < ArraySize(memPools); ++i) {
            if ((ptrdiff_t)mem < (ptrdiff_t)memPools[i].endOfPool) {
                MemBlock* block = (MemBlock*)mem;
                block->next = memPools[i].freeList;
                memPools[i].freeList = block;
                //printf("AJ_Free pool %d\n", memPools[i].size);
                break;
            }
        }
        assert(i < ArraySize(memPools));
    }
}