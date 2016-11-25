/******************************************************************************
 *
 *
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

#include <gtest/gtest.h>

extern "C" {
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_status.h>
#include <ajtcl/aj_util.h>

extern void _AJ_NVRAM_ResetLayout();
extern uint8_t isOldNVRAMLayout;
}
/*
 * For test purposes we want to compare with old deprecated API
 */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#define SENTINEL_SIZE 4
#define HEADER_SIZE 4
#define MAX_ENTRY_SIZE_OLD_LAYOUT (AJ_NVRAM_SIZE - SENTINEL_SIZE - HEADER_SIZE)
#define MAX_ENTRY_SIZE_NEW_LAYOUT (AJ_NVRAM_SIZE_APPS - SENTINEL_SIZE - HEADER_SIZE)
#define ENTRY_ID AJ_NVRAM_ID_APPS_BEGIN


TEST(NVRAMTest, NewLayoutInit)
{
    _AJ_NVRAM_ResetLayout();
    AJ_NVRAM_Init();
    ASSERT_EQ(AJ_ERR_INVALID, AJ_NVRAM_Init_NewLayout());
    _AJ_NVRAM_ResetLayout();
    ASSERT_EQ(AJ_OK, AJ_NVRAM_Init_NewLayout());
    ASSERT_EQ(AJ_ERR_UNEXPECTED, AJ_NVRAM_Init_NewLayout());
}

/* helper function */
static void _createNVRAMEntry(uint32_t entryId, uint32_t entrySize)
{
    AJ_NV_DATASET* nvramHandleWrite = NULL;
    nvramHandleWrite = AJ_NVRAM_Open(entryId, "w", entrySize);
    ASSERT_NE(static_cast<AJ_NV_DATASET*>(0), nvramHandleWrite);
    ASSERT_EQ(AJ_OK, AJ_NVRAM_Close(nvramHandleWrite));
    ASSERT_TRUE(AJ_NVRAM_Exist(entryId));
}

/* helper function */
static void _deleteNVRAMEntry(uint32_t entryId)
{
    ASSERT_EQ(AJ_OK, AJ_NVRAM_Delete(ENTRY_ID));
    ASSERT_FALSE(AJ_NVRAM_Exist(entryId));
}

static void testNewApi()
{
    AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS);
    uint32_t maxEntrySize = AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_APPS_BLOCK) - HEADER_SIZE;
    uint8_t totalSentinelsDataSize = SENTINEL_SIZE;
    if (isOldNVRAMLayout) {
        ASSERT_EQ(MAX_ENTRY_SIZE_OLD_LAYOUT, maxEntrySize);
    } else {
        ASSERT_EQ(MAX_ENTRY_SIZE_NEW_LAYOUT, maxEntrySize);
        /* In case of new NVRAM layout each block starts with sentinel data */
        uint8_t blockId = AJ_NVRAM_ID_ALL_BLOCKS + 1;
        uint8_t numberOfBlocks = 0;
        while (blockId++ < AJ_NVRAM_ID_END_SENTINEL) {
            ++numberOfBlocks;
        }
        totalSentinelsDataSize = SENTINEL_SIZE * numberOfBlocks;
    }

    /* Test if NVRAM used and free size is as expected after clering whole NVRAM */
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), AJ_NVRAM_SIZE - totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), SENTINEL_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), maxEntrySize + HEADER_SIZE);

    AJ_NV_DATASET* nvramHandleWrite = NULL;
    AJ_NV_DATASET* nvramHandleRead = NULL;

    /* Test some basic NVRAM read and write */
    nvramHandleRead = AJ_NVRAM_Open(ENTRY_ID, "r", maxEntrySize);
    ASSERT_EQ(static_cast<AJ_NV_DATASET*>(0), nvramHandleRead);
    nvramHandleWrite = AJ_NVRAM_Open(ENTRY_ID, "w", maxEntrySize);
    ASSERT_NE(static_cast<AJ_NV_DATASET*>(0), nvramHandleWrite);
    uint8_t* buffer = new uint8_t[maxEntrySize];
    uint8_t byteData = 5;
    memset(buffer, byteData, maxEntrySize);
    ASSERT_EQ(maxEntrySize, AJ_NVRAM_Write(buffer, maxEntrySize, nvramHandleWrite));
    ASSERT_EQ(AJ_OK, AJ_NVRAM_Close(nvramHandleWrite));
    nvramHandleWrite = NULL;
    memset(buffer, 0, maxEntrySize);
    nvramHandleRead = AJ_NVRAM_Open(ENTRY_ID, "r", maxEntrySize);
    ASSERT_NE(static_cast<AJ_NV_DATASET*>(0), nvramHandleRead);
    ASSERT_EQ(maxEntrySize, AJ_NVRAM_Read(buffer, maxEntrySize, nvramHandleRead));
    uint32_t bit = maxEntrySize;
    while (bit > 0) {
        --bit;
        EXPECT_EQ(buffer[bit], byteData) << "Wrong byte value at: " << bit;
    }
    delete[] buffer;
    ASSERT_EQ(AJ_OK, AJ_NVRAM_Close(nvramHandleRead));
    nvramHandleRead = NULL;

    /* Test if NVRAM used and free size is as expected before and after deleting entry */
    _createNVRAMEntry(ENTRY_ID, maxEntrySize);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), maxEntrySize + totalSentinelsDataSize + HEADER_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), AJ_NVRAM_SIZE - maxEntrySize - totalSentinelsDataSize - HEADER_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), maxEntrySize + SENTINEL_SIZE + HEADER_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), 0);
    _deleteNVRAMEntry(ENTRY_ID);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), AJ_NVRAM_SIZE - totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), SENTINEL_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), maxEntrySize + HEADER_SIZE);

    uint8_t entrySize = 16;

    /* Test if NVRAM used and free size is as expected after clering whole NVRAM */
    _createNVRAMEntry(ENTRY_ID, entrySize);
    AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), AJ_NVRAM_SIZE - totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), SENTINEL_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), maxEntrySize + HEADER_SIZE);

    /* Test if NVRAM used and free size is as expected after clering affected NVRAM block */
    _createNVRAMEntry(ENTRY_ID, entrySize);
    AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_ID_APPS_BLOCK);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS), AJ_NVRAM_SIZE - totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), SENTINEL_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_APPS_BLOCK), maxEntrySize + HEADER_SIZE);
}


TEST(NVRAMTest, NewApiWithNewLayout)
{
    _AJ_NVRAM_ResetLayout();
    AJ_NVRAM_Init_NewLayout();

    testNewApi();
}


TEST(NVRAMTest, NewApiWithOldLayout)
{
    _AJ_NVRAM_ResetLayout();
    AJ_NVRAM_Init();

    testNewApi();
}


static void testOldApi()
{
    AJ_NVRAM_Clear();
    uint32_t maxEntrySize;
    uint8_t totalSentinelsDataSize = SENTINEL_SIZE;
    if (isOldNVRAMLayout) {
        maxEntrySize = MAX_ENTRY_SIZE_OLD_LAYOUT;
    } else {
        maxEntrySize = MAX_ENTRY_SIZE_NEW_LAYOUT;
        /* In case of new NVRAM layout each block starts with sentinel data */
        uint8_t blockId = AJ_NVRAM_ID_ALL_BLOCKS + 1;
        uint8_t numberOfBlocks = 0;
        while (blockId++ < AJ_NVRAM_ID_END_SENTINEL) {
            ++numberOfBlocks;
        }
        totalSentinelsDataSize = SENTINEL_SIZE * numberOfBlocks;
    }

    /* Test if NVRAM used and free size is as expected after clering whole NVRAM */
    EXPECT_EQ(AJ_NVRAM_GetSize(), totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining(), AJ_NVRAM_SIZE - totalSentinelsDataSize);

    AJ_NV_DATASET* nvramHandleWrite = NULL;
    AJ_NV_DATASET* nvramHandleRead = NULL;

    /* Test some basic NVRAM read and write */
    nvramHandleRead = AJ_NVRAM_Open(ENTRY_ID, "r", maxEntrySize);
    ASSERT_EQ(static_cast<AJ_NV_DATASET*>(0), nvramHandleRead);
    nvramHandleWrite = AJ_NVRAM_Open(ENTRY_ID, "w", maxEntrySize);
    ASSERT_NE(static_cast<AJ_NV_DATASET*>(0), nvramHandleWrite);
    uint8_t* buffer = new uint8_t[maxEntrySize];
    uint8_t byteData = 5;
    memset(buffer, byteData, maxEntrySize);
    ASSERT_EQ(maxEntrySize, AJ_NVRAM_Write(buffer, maxEntrySize, nvramHandleWrite));
    ASSERT_EQ(AJ_OK, AJ_NVRAM_Close(nvramHandleWrite));
    nvramHandleWrite = NULL;
    memset(buffer, 0, maxEntrySize);
    nvramHandleRead = AJ_NVRAM_Open(ENTRY_ID, "r", maxEntrySize);
    ASSERT_NE(static_cast<AJ_NV_DATASET*>(0), nvramHandleRead);
    ASSERT_EQ(maxEntrySize, AJ_NVRAM_Read(buffer, maxEntrySize, nvramHandleRead));
    uint32_t bit = maxEntrySize;
    while (bit > 0) {
        --bit;
        EXPECT_EQ(buffer[bit], byteData) << "Wrong byte value: " << bit;
    }
    delete[] buffer;
    ASSERT_EQ(AJ_OK, AJ_NVRAM_Close(nvramHandleRead));
    nvramHandleRead = NULL;

    /* Test if NVRAM used and free size is as expected before and after deleting entry */
    _createNVRAMEntry(ENTRY_ID, maxEntrySize);
    EXPECT_EQ(AJ_NVRAM_GetSize(), maxEntrySize + totalSentinelsDataSize + HEADER_SIZE);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining(), AJ_NVRAM_SIZE - maxEntrySize - totalSentinelsDataSize - HEADER_SIZE);
    _deleteNVRAMEntry(ENTRY_ID);
    EXPECT_EQ(AJ_NVRAM_GetSize(), totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining(), AJ_NVRAM_SIZE - totalSentinelsDataSize);

    uint8_t entrySize = 16;

    /* Test if NVRAM used and free size is as expected after clering whole NVRAM */
    _createNVRAMEntry(ENTRY_ID, entrySize);
    AJ_NVRAM_Clear();
    EXPECT_EQ(AJ_NVRAM_GetSize(), totalSentinelsDataSize);
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining(), AJ_NVRAM_SIZE - totalSentinelsDataSize);
}


static void _expectOldNVRAMfull()
{
    EXPECT_EQ(AJ_NVRAM_SIZE, AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
    EXPECT_EQ(AJ_NVRAM_GetSize(), AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
    EXPECT_EQ(0, AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining(), AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
}


static void _expectOldNVRAMclear()
{
    EXPECT_EQ(SENTINEL_SIZE, AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
    EXPECT_EQ(AJ_NVRAM_GetSize(), AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
    EXPECT_EQ(AJ_NVRAM_SIZE - SENTINEL_SIZE, AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
    EXPECT_EQ(AJ_NVRAM_GetSizeRemaining(), AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS));
}


static void testApiCompatibilityWithOldLayout()
{
    /* prepare */
    AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS);

    /* prove equality of new and old GetSize and GetSizeRemaining */
    _expectOldNVRAMclear();
    _createNVRAMEntry(ENTRY_ID, MAX_ENTRY_SIZE_OLD_LAYOUT);
    _expectOldNVRAMfull();

    /* test new AJ_NVRAM_Clear_NewLayout */
    AJ_NVRAM_Clear_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS);
    _expectOldNVRAMclear();

    /* prepare */
    _createNVRAMEntry(ENTRY_ID, 16);

    /* test old AJ_NVRAM_Clear */
    AJ_NVRAM_Clear();
    _expectOldNVRAMclear();
}


TEST(NVRAMTest, ApiCompatibilityWithOldLayout)
{
    _AJ_NVRAM_ResetLayout();
    AJ_NVRAM_Init();

    testApiCompatibilityWithOldLayout();
}


TEST(NVRAMTest, OldApiWithOldLayout)
{
    _AJ_NVRAM_ResetLayout();
    AJ_NVRAM_Init();

    testApiCompatibilityWithOldLayout();

    testOldApi();
}


TEST(NVRAMTest, OldApiWithNewLayout)
{
    _AJ_NVRAM_ResetLayout();
    AJ_NVRAM_Init_NewLayout();

    testOldApi();
}