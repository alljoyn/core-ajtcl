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

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_crypto.h>

/* Forward Declaration */
AJ_Status CreateTrailOfBreadcrumbs(void);
AJ_Status FollowTrailOfBreadcrumbs(void);

const int8_t AJTestNvramReadFailure  = -1;
const int8_t AJTestNvramWriteFailure = -1;

char AJTestReadMode[]  = { AJ_NV_DATASET_MODE_READ, '\0' };
char AJTestWriteMode[] = { AJ_NV_DATASET_MODE_WRITE, '\0' };

/*
 * When an item is stored in NVRAM, the number of bytes occupied
 * equals the size of the item stored itself, plus the overhead to
 * to store metadata (viz. id and some other information).
 *
 * The most accurate way to measure this would be to actually write
 * an item to the NVRAM and compare the before and after sizes.
 *
 * A rough estimate would be the 'visible' size of AJ_NV_DATASET structure.
 * (the member void* internal, is opaque to the application)
 */
static const uint16_t estimatedOverheadPerNvramItem = sizeof(AJ_NV_DATASET);

static const char sensumManifestum[] = "AllJoyn - The cultissima aditus ad IoT";

/* starting id for trail of crumbs */
static const uint16_t smId = 0x8421;
/* id where number of crumbs is stored */
static const uint16_t countId = 0x8193;

static uint16_t lengthOfBreadcrumbTrail = 0;

int AJ_Main(void)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_NVRAM_Init();

    AJ_Printf("\nAllJoyn Release: %s\n\n", AJ_GetVersion());

    /*
     * The very first thing the test application does is to follow the trail of
     * breadcrumbs, if available.
     */
    status = FollowTrailOfBreadcrumbs();
    if (AJ_OK == status) {
        AJ_Printf("PASS: Successfully read the known message from NVRAM and "
                  "it is as expected. Done with the test.\n");

        return status;
    } else {
        AJ_Printf("INFO: No old remnants of a previous test run found.\n");
    }

    /*
     * The very last thing the test application does is to create the trail of
     * breadcrumbs, to be compared upon start.
     */
    status = CreateTrailOfBreadcrumbs();
    if (AJ_OK == status) {
        AJ_Printf("INFO: Successfully wrote the known message to NVRAM.\n");

        AJ_Reboot(); /* Reboot the target, if available */
    } else {
        AJ_Printf("ERROR: CreateTrailOfBreadcrumbs failed: %s (code: %u)\n", AJ_StatusText(status), status);
    }

    AJ_Printf("INFO: Completed running the test. Exiting...\n");

    return status;
}

AJ_Status CreateTrailOfBreadcrumbs(void)
{
    uint16_t minNvramSpaceNeeded;
    uint16_t currentAvailableNvramSpace;


    uint16_t someNvramId = 0;
    AJ_NV_DATASET* someDataHandle = NULL;

    uint8_t sizeOfEachSlice;
    uint16_t i;

    size_t numBytesExpectingToWrite;
    size_t numBytesActuallyWritten;

    /*
     * Test program would write (place breadcrumbs) over the NVRAM, anyway.
     */
    AJ_NVRAM_Clear();

    currentAvailableNvramSpace = AJ_NVRAM_GetSizeRemaining();

    /*
     * At minimum, the test needs to store:
     * a. The message itself
     * b. The number of breadcrumbs in the trail (the mininum value is 1)
     *    (this is essentially the value held by lengthOfBreadcrumbTrail)
     */
    minNvramSpaceNeeded = (estimatedOverheadPerNvramItem + sizeof(sensumManifestum)) +
                          (estimatedOverheadPerNvramItem + sizeof(lengthOfBreadcrumbTrail));

    if (currentAvailableNvramSpace < minNvramSpaceNeeded) {
        AJ_Printf("ERROR: Available NVRAM space (%u bytes) is less than needed (%u bytes).\n", currentAvailableNvramSpace, minNvramSpaceNeeded);
        return AJ_ERR_RESOURCES;
    }

    /*
     * Any remaining space can be used to add more breadcrumbs.
     * max_num_bread_crumbs = nvram_size_available / size_occupied_by_each_crumb
     *
     * size_occupied_by_each_crumb = estimatedOverheadPerNvramItem + sizeof(id)
     */
    lengthOfBreadcrumbTrail = (currentAvailableNvramSpace - minNvramSpaceNeeded) /
                              (estimatedOverheadPerNvramItem  + sizeof(someNvramId));

    /*
     * Create the trail of bread crumbs starting at smId
     *
     * Generate a random list of nvram ids, lengthOfBreadcrumbTrail number of
     * elements. The list should not have any duplicates and should not include
     * marker ids viz. smId and countId.
     *
     * This is necessary to ensure that the trail of breadcrumbs is without
     * any loops. The simplest way to generate a list of unique nvram ids
     * would be to divide the available space into equal slices and generate
     * one id from each slice.
     *
     * The starting id is AJ_NVRAM_ID_APPS_BEGIN and the ending id is 0xFFFF.
     *
     * There are a total of (lengthOfBreadcrumbTrail + 1) items to
     * go through, including the starting point smId.
     */

    sizeOfEachSlice = (0xFFFF - AJ_NVRAM_ID_APPS_BEGIN) / lengthOfBreadcrumbTrail;

    /* The starting point has to be the constant marker, smId */
    someNvramId = smId;
    for (i = 0; i < lengthOfBreadcrumbTrail + 1; i++) {
        uint8_t randByte;
        uint16_t startId;
        uint16_t nextId;

        void* pointerToData;

        AJ_RandBytes(&randByte, sizeof(randByte));
        startId = AJ_NVRAM_ID_APPS_BEGIN + sizeOfEachSlice * i;

        nextId = startId + randByte % sizeOfEachSlice;

        /* Ensure uniqueness of id - no conflicts with well-known markers */
        if (smId == nextId || countId == nextId) {
            nextId += (0 == i % 2) ? -1 : 1;
        }

        numBytesExpectingToWrite =  (lengthOfBreadcrumbTrail != i) ? sizeof(nextId) : sizeof(sensumManifestum);

        currentAvailableNvramSpace = AJ_NVRAM_GetSizeRemaining();

        someDataHandle = AJ_NVRAM_Open(someNvramId, AJTestWriteMode, numBytesExpectingToWrite);

        if (NULL == someDataHandle) {
            /* Cannot proceed any further due to failed breadcrumb access */
            return AJ_ERR_NVRAM_WRITE;
        }

        pointerToData = (lengthOfBreadcrumbTrail != i) ? (void*) (&nextId) : (void*) sensumManifestum;
        numBytesActuallyWritten = AJ_NVRAM_Write(pointerToData,
                                                 numBytesExpectingToWrite,
                                                 someDataHandle);

        /* done writing the data, can close the handle */
        if (AJ_OK != AJ_NVRAM_Close(someDataHandle)) {
            AJ_Printf("WARN: For id: %u, AJ_NVRAM_Close did NOT return %s (code: %u)\n", someNvramId, AJ_StatusText(AJ_OK), AJ_OK);
        }

        if (AJTestNvramWriteFailure == numBytesActuallyWritten ||
            numBytesExpectingToWrite != numBytesActuallyWritten) {
            /* Cannot proceed any further due to breadcrumb write failure */
            return AJ_ERR_NVRAM_WRITE;
        }

        /*
         * The write has been successful.
         *
         * Check whether estimatedOverheadPerNvramItem (rough estimate) is
         * accurate. Overestimating estimatedOverheadPerNvramItem is fine
         * (erring on the side on caution).
         */
        if (estimatedOverheadPerNvramItem < currentAvailableNvramSpace - AJ_NVRAM_GetSizeRemaining() - numBytesExpectingToWrite) {
            AJ_Printf("ERROR: The estimated overhead per NVRAM item (%u bytes) is not accurate. It needs to be increased.\n", estimatedOverheadPerNvramItem);
            return AJ_ERR_FAILURE;
        }

        /* Move to the next breadcrumb */
        someNvramId = nextId;
    }

    /*
     * All the items are written.
     * Write the value of lengthOfBreadcrumbTrail
     */
    someDataHandle = AJ_NVRAM_Open(countId, AJTestWriteMode, sizeof(lengthOfBreadcrumbTrail));

    if (NULL == someDataHandle) {
        return AJ_ERR_NVRAM_WRITE;
    }

    numBytesExpectingToWrite = sizeof(lengthOfBreadcrumbTrail);
    numBytesActuallyWritten = AJ_NVRAM_Write((void*)&lengthOfBreadcrumbTrail,
                                             numBytesExpectingToWrite,
                                             someDataHandle);

    /* done writing the data, can close the handle */
    if (AJ_OK != AJ_NVRAM_Close(someDataHandle)) {
        AJ_Printf("WARN: For id: %u, AJ_NVRAM_Close did NOT return %s (code: %u)\n", countId, AJ_StatusText(AJ_OK), AJ_OK);
    }

    if (AJTestNvramWriteFailure == numBytesActuallyWritten ||
        numBytesExpectingToWrite != numBytesActuallyWritten) {
        return AJ_ERR_NVRAM_WRITE;
    }

    return AJ_OK;
}

AJ_Status FollowTrailOfBreadcrumbs(void)
{
    static char scratchPad[sizeof(sensumManifestum)];

    uint16_t someNvramId = 0;
    AJ_NV_DATASET* someDataHandle = NULL;

    size_t numBytesExpectingToRead;
    size_t numBytesActuallyRead;

    uint16_t i;

    /*
     * As long as NVRAM wasn't cleared between two successive runs of
     * the test, it should be possible to read the known data written at
     * the very end of the test by the previous run.
     *
     * The first item to read is the number of breadcrumbs.
     */

    if (1 != AJ_NVRAM_Exist(countId)) {
        /* cannot find the marker countId */
        return AJ_ERR_NVRAM_READ;
    }

    someDataHandle = AJ_NVRAM_Open(countId, AJTestReadMode, 0);
    if (NULL == someDataHandle) {
        /* cannot open the marker countId */
        return AJ_ERR_NVRAM_READ;
    }

    numBytesExpectingToRead = sizeof(lengthOfBreadcrumbTrail);
    numBytesActuallyRead = AJ_NVRAM_Read((void*)&lengthOfBreadcrumbTrail,
                                         numBytesExpectingToRead,
                                         someDataHandle);

    if (AJ_OK != AJ_NVRAM_Close(someDataHandle)) {
        AJ_Printf("WARN: For id: %u, AJ_NVRAM_Close did NOT return %s (code: %u)\n", countId, AJ_StatusText(AJ_OK), AJ_OK);
    }

    if (AJTestNvramReadFailure == numBytesActuallyRead ||
        numBytesExpectingToRead != numBytesActuallyRead) {
        /* could not read from the marker countId */
        return AJ_ERR_NVRAM_READ;
    }

    /*
     * Follow the trail of bread crumbs starting at smId
     */
    someNvramId = smId;
    for (i  = 0; i < lengthOfBreadcrumbTrail + 1; i++) {
        uint8_t isIdPresent = AJ_NVRAM_Exist(someNvramId);

        void* pointerToData = (lengthOfBreadcrumbTrail != i) ? (void*) &someNvramId : (void*) scratchPad;

        someDataHandle = (1 == isIdPresent) ? AJ_NVRAM_Open(someNvramId, AJTestReadMode, 0) : NULL;

        if (NULL == someDataHandle) {
            /* Cannot proceed any further due to failed breadcrumb access */
            return AJ_ERR_NVRAM_READ;
        }

        numBytesExpectingToRead =  (lengthOfBreadcrumbTrail != i) ? sizeof(someNvramId) : sizeof(sensumManifestum);
        numBytesActuallyRead = AJ_NVRAM_Read(pointerToData,
                                             numBytesExpectingToRead,
                                             someDataHandle);

        /* done reading the data, can close the handle */
        if (AJ_OK != AJ_NVRAM_Close(someDataHandle)) {
            AJ_Printf("WARN: For id: %u, AJ_NVRAM_Close did NOT return %s (code: %u)\n", someNvramId, AJ_StatusText(AJ_OK), AJ_OK);
        }

        if (AJTestNvramReadFailure == numBytesActuallyRead ||
            numBytesExpectingToRead != numBytesActuallyRead) {
            /* Cannot proceed any further due to breadcrumb read failure */
            return AJ_ERR_NVRAM_READ;
        }


        if (lengthOfBreadcrumbTrail == i) {
            /* Final crumb where message has been retrieved */
            return (0 == strcmp(scratchPad, sensumManifestum)) ? AJ_OK : AJ_ERR_NVRAM_READ;
        }
    }

    return AJ_OK;
}

#ifdef AJ_MAIN
int main(void)
{
    return AJ_Main();
}
#endif
