#ifndef _AJ_CREDS_H
#define _AJ_CREDS_H
/**
 * @file aj_creds.h
 * @defgroup aj_creads Credentials Management
 * @{
 */
/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
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

#include "aj_target.h"
#include "aj_guid.h"
#include "aj_status.h"

/**
 * Credentials for a remote peer
 */
typedef struct _AJ_PeerCred {
    AJ_GUID guid;        /**< GUID for the peer */
    uint8_t secret[24];  /**< secret keying data */
} AJ_PeerCred;

/**
 * Write a peer credential to NVRAM
 *
 * @param peerCred  The credentials to write.
 *
 * @return
 *          - AJ_OK if the credentials were written.
 *          - AJ_ERR_RESOURCES if there is no space to write the credentials
 */
AJ_Status AJ_StoreCredential(AJ_PeerCred* peerCred);

/**
 * Delete a peer credential from NVRAM
 *
 * @param peerGuid  The guid for the peer that has credentials to delete.
 *
 * @return
 *          - AJ_OK if the credentials were deleted.
 */
AJ_Status AJ_DeleteCredential(const AJ_GUID* peerGuid);

/**
 * Clears all peer credentials.
 *
 * @return
 *          - AJ_OK if all credentials have been deleted
 */
AJ_Status AJ_ClearCredentials(void);

/**
 * Get the credentials for a specific remote peer from NVRAM
 *
 * @param peerGuid  The GUID for the remote peer.
 * @param peerCred  Pointer to a bufffer that has enough space to store the credentials for a specific remote peer identified by a GUID
 *
 * @return  AJ_OK if the credentials for the specific remote peer exist and are copied into the buffer
 *          AJ_ERR_FAILURE otherwise.
 */
AJ_Status AJ_GetRemoteCredential(const AJ_GUID* peerGuid, AJ_PeerCred* peerCred);

/**
 * Get the GUID for this peer. If this is the first time the GUID has been requested this function
 * will generate the GUID and store it in NVRAM
 *
 * @param localGuid Pointer to a bufffer that has enough space to store the local GUID
 *
 * @return  AJ_OK if the local GUID is copied into the buffer.
 */
AJ_Status AJ_GetLocalGUID(AJ_GUID* localGuid);

/**
 * @}
 */
#endif
