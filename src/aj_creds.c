/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE CREDS

#include "aj_target.h"
#include "aj_creds.h"
#include "aj_status.h"
#include "aj_crypto.h"
#include "aj_nvram.h"
#include "aj_debug.h"
#include "aj_config.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCREDS = 0;
#endif

uint16_t FindCredsEmptySlot()
{
    uint16_t id = AJ_REMOTE_CREDS_NV_ID_BEGIN;
    for (; id < AJ_REMOTE_CREDS_NV_ID_END; id++) {
        if (!AJ_NVRAM_Exist(id)) {
            return id;
        }
    }
    return 0;
}

uint16_t FindCredsByGUID(const AJ_GUID* peerGuid)
{
    uint16_t id = AJ_REMOTE_CREDS_NV_ID_BEGIN;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("FindCredsByGUID()\n"));

    for (; id < AJ_REMOTE_CREDS_NV_ID_END; id++) {
        if (AJ_NVRAM_Exist(id)) {
            handle = AJ_NVRAM_Open(id, "r", 0);
            if (!handle) {
                AJ_ErrPrintf(("FindCredsByGUID(): fail to open data set with id = %d\n", id));
            } else {
                AJ_GUID guid;
                if (sizeof(AJ_GUID) != AJ_NVRAM_Read(&guid, sizeof(AJ_GUID), handle)) {
                    AJ_ErrPrintf(("FindCredsByGUID(): fail to %zu bytes from data set with id = %d\n", sizeof(AJ_GUID), id));
                    AJ_NVRAM_Close(handle);
                    continue;
                }
                if (memcmp(peerGuid, &guid, sizeof(AJ_GUID)) == 0) {
                    AJ_NVRAM_Close(handle);
                    return id;
                }
                AJ_NVRAM_Close(handle);
            }
        }
    }
    return 0;
}

AJ_Status UpdatePeerCreds(AJ_PeerCred* peerCred, uint16_t id)
{
    AJ_Status status = AJ_OK;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("UpdatePeerCreds(peerCred=0x%p, id=%d.)\n", peerCred, id));

    handle = AJ_NVRAM_Open(id, "w", sizeof(AJ_PeerCred));
    if (!handle) {
        AJ_ErrPrintf(("UpdatePeerCreds(): AJ_ERR_FAILURE\n"));
        status = AJ_ERR_FAILURE;
    } else {
        if (peerCred) {
            if (sizeof(AJ_PeerCred) != AJ_NVRAM_Write(peerCred, sizeof(AJ_PeerCred), handle)) {
                AJ_ErrPrintf(("UpdatePeerCreds(): AJ_ERR_FAILURE\n"));
                status = AJ_ERR_FAILURE;
            }
        }
        AJ_NVRAM_Close(handle);
    }
    return status;
}

/**
 * Write a credential to a free slot in NVRAM
 */
AJ_Status AJ_StoreCredential(AJ_PeerCred* peerCred)
{
    AJ_Status status = AJ_OK;
    uint16_t id;

    AJ_InfoPrintf(("UpdatePeerCreds(peerCred=0x%p)\n", peerCred));

    id = FindCredsByGUID(&peerCred->guid);
    if (!id) {
        id = FindCredsEmptySlot();
        if (!id) {
            AJ_ClearCredentials();
            id = FindCredsEmptySlot();
        }
    }

    if (id) {
        status = UpdatePeerCreds(peerCred, id);
    } else {
        status = AJ_ERR_FAILURE;
        AJ_ErrPrintf(("AJ_StoreCredential(): AJ_ERR_FAILURE\n"));
    }
    return status;
}

AJ_Status AJ_DeleteCredential(const AJ_GUID* peerGuid)
{
    AJ_Status status = AJ_ERR_FAILURE;
    uint16_t id = FindCredsByGUID(peerGuid);
    AJ_InfoPrintf(("AJ_DeleteCredentional(peerCred=0x%p)\n", peerGuid));

    if (id > 0) {
        status = AJ_NVRAM_Delete(id);
    }
    return status;
}

AJ_Status AJ_GetLocalGUID(AJ_GUID* localGuid)
{
    AJ_Status status = AJ_ERR_FAILURE;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_GetLocalGUID(localGuid=0x%p)\n", localGuid));

    if (AJ_NVRAM_Exist(AJ_LOCAL_GUID_NV_ID)) {
        handle = AJ_NVRAM_Open(AJ_LOCAL_GUID_NV_ID, "r", 0);
        if (handle) {
            size_t size;
            size = AJ_NVRAM_Read(localGuid, sizeof(AJ_GUID), handle);
            AJ_ASSERT(sizeof(AJ_GUID) == size);
            AJ_NVRAM_Close(handle);
            status = AJ_OK;
        }
    } else {
        AJ_RandBytes((uint8_t*)localGuid, sizeof(AJ_GUID));
        handle = AJ_NVRAM_Open(AJ_LOCAL_GUID_NV_ID, "w", sizeof(AJ_GUID));
        if (handle) {
            size_t size;
            size = AJ_NVRAM_Write(localGuid, sizeof(AJ_GUID), handle);
            AJ_ASSERT(sizeof(AJ_GUID) == size);
            AJ_NVRAM_Close(handle);
            status = AJ_OK;
        }
    }
    return status;
}

AJ_Status AJ_GetRemoteCredential(const AJ_GUID* peerGuid, AJ_PeerCred* peerCreds)
{
    AJ_Status status = AJ_ERR_FAILURE;
    uint16_t id;

    AJ_InfoPrintf(("AJ_GetRemoteCredential(peerGuid=0x%p, peerCreds=0x%p)\n", peerGuid, peerCreds));

    id = FindCredsByGUID(peerGuid);
    if (id > 0) {
        AJ_NV_DATASET* handle = AJ_NVRAM_Open(id, "r", 0);
        if (handle) {
            size_t size;
            size = AJ_NVRAM_Read(peerCreds, sizeof(AJ_PeerCred), handle);
            AJ_ASSERT(sizeof(AJ_PeerCred) == size);
            AJ_NVRAM_Close(handle);
            status = AJ_OK;
        }
    }
    return status;
}

AJ_Status AJ_ClearCredentials(void)
{
    AJ_Status status = AJ_OK;
    uint16_t id = AJ_REMOTE_CREDS_NV_ID_BEGIN;

    AJ_InfoPrintf(("AJ_ClearCredentials()\n"));

    for (; id < AJ_REMOTE_CREDS_NV_ID_END; ++id) {
        AJ_NVRAM_Delete(id);
    }

    return status;
}
