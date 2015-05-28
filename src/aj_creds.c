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
#include "aj_crypto_sha2.h"
#include "aj_util.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCREDS = 0;
#endif

static void CredFieldFree(AJ_CredField* field)
{
    if (field && field->data) {
        AJ_MemZeroSecure(field->data, field->size);
        AJ_Free(field->data);
        field->data = NULL;
    }
}

static AJ_Status CredFieldGet(AJ_CredField* field, uint8_t size, AJ_NV_DATASET* handle)
{
    /* Read size */
    field->size = 0;
    if (size != AJ_NVRAM_Read(&field->size, size, handle)) {
        return AJ_ERR_FAILURE;
    }
    /* Read data */
    field->data = NULL;
    if (field->size) {
        field->data = (uint8_t*) AJ_Malloc(field->size);
        if (!field->data) {
            return AJ_ERR_FAILURE;
        }
        if (field->size != AJ_NVRAM_Read(field->data, field->size, handle)) {
            return AJ_ERR_FAILURE;
        }
    }

    return AJ_OK;
}

static AJ_Status CredFieldSet(const AJ_CredField* field, uint8_t size, AJ_NV_DATASET* handle)
{
    /* Write size */
    if (size != AJ_NVRAM_Write((uint8_t*) &field->size, size, handle)) {
        return AJ_ERR_FAILURE;
    }
    /* Write data */
    if (field->size) {
        if (field->size != AJ_NVRAM_Write((uint8_t*) field->data, field->size, handle)) {
            return AJ_ERR_FAILURE;
        }
    }

    return AJ_OK;
}

static AJ_Status CredHeadGet(AJ_CredHead* head, AJ_NV_DATASET* handle)
{
    AJ_Status status;

    /* Read type */
    if (sizeof (head->type) != AJ_NVRAM_Read(&head->type, sizeof (head->type), handle)) {
        return AJ_ERR_FAILURE;
    }
    /* Read id */
    status = CredFieldGet(&head->id, sizeof (uint8_t), handle);
    if (AJ_OK != status) {
        return AJ_ERR_FAILURE;
    }

    return status;
}

void AJ_CredHeadFree(AJ_CredHead* head)
{
    AJ_InfoPrintf(("AJ_CredHeadFree(head=%p)\n", head));

    if (head) {
        CredFieldFree(&head->id);
    }
}

static AJ_Status CredHeadSet(const AJ_CredHead* head, AJ_NV_DATASET* handle)
{
    AJ_Status status;

    /* Write type */
    if (sizeof (head->type) != AJ_NVRAM_Write((uint8_t*) &head->type, sizeof (head->type), handle)) {
        return AJ_ERR_FAILURE;
    }
    /* Write id */
    status = CredFieldSet(&head->id, sizeof (uint8_t), handle);
    if (AJ_OK != status) {
        return AJ_ERR_FAILURE;
    }

    return status;
}

void AJ_CredBodyFree(AJ_CredBody* body)
{
    AJ_InfoPrintf(("AJ_CredBodyFree(body=%p)\n", body));

    if (body) {
        CredFieldFree(&body->association);
        CredFieldFree(&body->data);
    }
}

static AJ_Status CredBodyGet(AJ_CredBody* body, AJ_NV_DATASET* handle)
{
    AJ_Status status;

    /* Read expiration */
    if (sizeof (body->expiration) != AJ_NVRAM_Read(&body->expiration, sizeof (body->expiration), handle)) {
        return AJ_ERR_FAILURE;
    }
    /* Read association */
    status = CredFieldGet(&body->association, sizeof (uint8_t), handle);
    if (AJ_OK != status) {
        return AJ_ERR_FAILURE;
    }
    /* Read data */
    status = CredFieldGet(&body->data, sizeof (uint16_t), handle);
    if (AJ_OK != status) {
        return AJ_ERR_FAILURE;
    }

    return status;
}

static AJ_Status CredBodySet(const AJ_CredBody* body, AJ_NV_DATASET* handle)
{
    AJ_Status status;

    /* Write expiration */
    if (sizeof (body->expiration) != AJ_NVRAM_Write((uint8_t*) &body->expiration, sizeof (body->expiration), handle)) {
        return AJ_ERR_FAILURE;
    }
    /* Write association */
    status = CredFieldSet(&body->association, sizeof (uint8_t), handle);
    if (AJ_OK != status) {
        return AJ_ERR_FAILURE;
    }
    /* Write data */
    status = CredFieldSet(&body->data, sizeof (uint16_t), handle);
    if (AJ_OK != status) {
        return AJ_ERR_FAILURE;
    }

    return status;
}

static size_t CredentialSize(const AJ_Cred* cred)
{
    // type(2):idLen(1):id(idLen):expiration(4):assLen(1):ass(assLen):dataLen(2):data(dataLen)
    return sizeof (cred->head.type) +
           sizeof (cred->head.id.size) + cred->head.id.size +
           sizeof (cred->body.expiration) +
           sizeof (cred->body.association.size) + cred->body.association.size +
           sizeof (cred->body.data.size) + cred->body.data.size;
}

void AJ_CredFree(AJ_Cred* cred)
{
    AJ_InfoPrintf(("AJ_CredFree(cred=%p)\n", cred));

    if (cred) {
        AJ_CredHeadFree(&cred->head);
        AJ_CredBodyFree(&cred->body);
    }
}

AJ_Status AJ_ReadCredential(AJ_Cred* cred, uint16_t slot)
{
    AJ_Status status;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_ReadCredential(cred=%p, slot=%d)\n", cred, slot));

    memset(cred, 0, sizeof (AJ_Cred));
    handle = AJ_NVRAM_Open(slot, "r", 0);
    if (!handle) {
        return AJ_ERR_FAILURE;
    }
    status = CredHeadGet(&cred->head, handle);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = CredBodyGet(&cred->body, handle);
    if (AJ_OK != status) {
        goto Exit;
    }

Exit:
    AJ_NVRAM_Close(handle);

    return status;
}

AJ_Status AJ_SetCredential(const AJ_Cred* cred, uint16_t slot)
{
    AJ_Status status = AJ_OK;
    AJ_NV_DATASET* handle;
    size_t len;

    AJ_InfoPrintf(("AJ_SetCredential(cred=%p, slot=%d)\n", cred, slot));

    len = CredentialSize(cred);
    handle = AJ_NVRAM_Open(slot, "w", len);
    if (!handle) {
        return AJ_ERR_FAILURE;
    }
    status = CredHeadSet(&cred->head, handle);
    if (AJ_OK != status) {
        AJ_NVRAM_Close(handle);
        return AJ_ERR_FAILURE;
    }
    status = CredBodySet(&cred->body, handle);
    if (AJ_OK != status) {
        AJ_NVRAM_Close(handle);
        return AJ_ERR_FAILURE;
    }
    AJ_NVRAM_Close(handle);

    return AJ_OK;
}

static uint16_t FindCredsEmptySlot()
{
    uint16_t id = AJ_CREDS_NV_ID_BEGIN;

    for (; id < AJ_CREDS_NV_ID_END; id++) {
        if (!AJ_NVRAM_Exist(id)) {
            return id;
        }
    }

    return 0;
}

static AJ_Status CompareHead(const AJ_CredHead* head, const AJ_CredHead* test)
{
    if (head->type != test->type) {
        return AJ_ERR_INVALID;
    }
    if (0 == head->id.size) {
        return AJ_OK;
    }
    if (head->id.size != test->id.size) {
        return AJ_ERR_INVALID;
    }
    if (0 != memcmp(head->id.data, test->id.data, head->id.size)) {
        return AJ_ERR_INVALID;
    }
    return AJ_OK;
}

static uint16_t FindCredential(const AJ_CredHead* head, AJ_CredBody* body, uint16_t slot)
{
    AJ_Status status;
    AJ_CredHead test;
    AJ_NV_DATASET* handle;

    for (; slot < AJ_CREDS_NV_ID_END; slot++) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        handle = AJ_NVRAM_Open(slot, "r", 0);
        if (!handle) {
            return 0;
        }
        status = CredHeadGet(&test, handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            return 0;
        }
        status = CompareHead(head, &test);
        AJ_CredHeadFree(&test);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            continue;
        }
        /* Found */
        if (body) {
            status = CredBodyGet(body, handle);
            if (AJ_OK != status) {
                slot = 0;
            }
        }
        AJ_NVRAM_Close(handle);
        return slot;
    }

    return 0; /* not found */
}

static uint16_t DeleteOldestCredential()
{
    AJ_Status status = AJ_ERR_INVALID;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;
    uint16_t oldestslot = 0;
    uint32_t oldestexp = 0xFFFFFFFF;
    AJ_Cred cred;

    AJ_InfoPrintf(("DeleteOldestCredential()\n"));

    for (; slot < AJ_CREDS_NV_ID_END; slot++) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        status = AJ_ReadCredential(&cred, slot);
        if (AJ_OK != status) {
            AJ_ErrPrintf(("DeleteOldestCredential(): fail to read type and id\n"));
            return AJ_ERR_FAILURE;
        }
        if (AJ_CRED_TYPE_GENERIC != cred.head.type) {
            AJ_CredFree(&cred);
            continue;
        }
        /* If older */
        if (cred.body.expiration <= oldestexp) {
            oldestexp = cred.body.expiration;
            oldestslot = slot;
        }
    }

    if (oldestslot) {
        AJ_InfoPrintf(("DeleteOldestCredential(): slot=%d exp=0x%08X\n", oldestslot, oldestexp));
        AJ_NVRAM_Delete(oldestslot);
    }

    return oldestslot;
}

AJ_Status AJ_GetCredential(const AJ_CredHead* head, AJ_CredBody* body)
{
    AJ_InfoPrintf(("AJ_GetCredential(head=%p, body=%p)\n", head, body));
    return FindCredential(head, body, AJ_CREDS_NV_ID_BEGIN) ? AJ_OK : AJ_ERR_UNKNOWN;
}

AJ_Status AJ_GetNextCredential(const AJ_CredHead* head, AJ_CredBody* body, uint16_t* slot)
{
    AJ_InfoPrintf(("AJ_GetNextCredential(head=%p, body=%p, slot=%d)\n", head, body, slot));
    *slot = FindCredential(head, body, *slot);
    return *slot ? AJ_OK : AJ_ERR_UNKNOWN;
}

AJ_Status AJ_StorePeerSecret(const AJ_GUID* guid, const uint8_t* secret,
                             const uint8_t len, uint32_t expiration)
{
    AJ_Cred cred;
    AJ_Status status;

    AJ_InfoPrintf(("AJ_StorePeerSecret(guid=%p, secret=%p, len=%d, expiration=0x%08X)\n", guid, secret, len, expiration));

    cred.head.type = AJ_CRED_TYPE_GENERIC;
    cred.head.id.size = sizeof (AJ_GUID);
    cred.head.id.data = (uint8_t*) guid;
    cred.body.expiration = expiration;
    cred.body.association.size = 0;
    cred.body.association.data = NULL;
    cred.body.data.size = len;
    cred.body.data.data = (uint8_t*) secret;
    status = AJ_StoreCredential(&cred);

    return status;
}

AJ_Status AJ_DeleteCredential(const AJ_CredHead* head)
{
    AJ_Status status = AJ_ERR_FAILURE;
    uint16_t slot = FindCredential(head, NULL, AJ_CREDS_NV_ID_BEGIN);

    AJ_InfoPrintf(("AJ_DeleteCredential(head=%p)\n", head));

    if (slot > 0) {
        status = AJ_NVRAM_Delete(slot);
    }

    return status;
}

AJ_Status AJ_DeletePeerCredential(const AJ_GUID* guid)
{
    AJ_CredHead head;

    head.type = AJ_CRED_TYPE_GENERIC;
    head.id.size = sizeof (AJ_GUID);
    head.id.data = (uint8_t*) guid;

    return AJ_DeleteCredential(&head);
}

AJ_Status AJ_ClearCredentials(uint16_t type)
{
    AJ_Status status = AJ_OK;
    uint16_t id = AJ_CREDS_NV_ID_BEGIN;
    AJ_CredHead head;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_ClearCredentials()\n"));

    for (; id < AJ_CREDS_NV_ID_END; ++id) {
        if (!AJ_NVRAM_Exist(id)) {
            continue;
        }
        if (type) {
            handle = AJ_NVRAM_Open(id, "r", 0);
            if (!handle) {
                return AJ_ERR_FAILURE;
            }
            status = CredHeadGet(&head, handle);
            if (AJ_OK != status) {
                AJ_NVRAM_Close(handle);
                return AJ_ERR_FAILURE;
            }
            if (type != head.type) {
                AJ_CredHeadFree(&head);
                AJ_NVRAM_Close(handle);
                continue;
            }
            AJ_CredHeadFree(&head);
            AJ_NVRAM_Close(handle);
        }
        AJ_NVRAM_Delete(id);
    }

    return status;
}

AJ_Status AJ_GetPeerCredential(const AJ_GUID* guid, AJ_Cred* cred)
{
    AJ_InfoPrintf(("AJ_GetPeerCredential(guid=%p, cred=%p)\n", guid, cred));

    cred->head.type = AJ_CRED_TYPE_GENERIC;
    cred->head.id.size = sizeof (AJ_GUID);
    cred->head.id.data = (uint8_t*) guid;

    return AJ_GetCredential(&cred->head, &cred->body);
}

AJ_Status AJ_GetLocal(uint16_t slot, uint8_t* data, size_t len)
{
    AJ_Status status = AJ_ERR_FAILURE;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_GetLocal(slot=%d, data=%p, len=%zu)\n", slot, data, len));

    if (AJ_NVRAM_Exist(slot)) {
        handle = AJ_NVRAM_Open(slot, "r", 0);
        if (handle) {
            if (len == AJ_NVRAM_Read(data, len, handle)) {
                status = AJ_OK;
            } else {
                AJ_ErrPrintf(("AJ_GetLocal(): fail to read slot length %zu bytes from slot = %d\n", len, slot));
            }
            status = AJ_NVRAM_Close(handle);
        }
    }

    return status;
}

AJ_Status AJ_SetLocal(uint16_t slot, uint8_t* data, size_t len)
{
    AJ_Status status = AJ_ERR_FAILURE;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_SetLocal(slot=%d, data=%p, len=%zu)\n", slot, data, len));

    handle = AJ_NVRAM_Open(slot, "w", len);
    if (handle) {
        if (len == AJ_NVRAM_Write(data, len, handle)) {
            status = AJ_OK;
        } else {
            AJ_ErrPrintf(("AJ_SetLocal(): fail to write slot length %zu bytes to slot = %d\n", len, slot));
        }
        status = AJ_NVRAM_Close(handle);
    }

    return status;
}

AJ_Status AJ_GetLocalGUID(AJ_GUID* guid)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_GetLocalGUID(guid=%p)\n", guid));

    status = AJ_GetLocal(AJ_LOCAL_GUID_NV_ID, (uint8_t*) guid, sizeof (AJ_GUID));
    if (AJ_OK != status) {
        AJ_RandBytes((uint8_t*) guid, sizeof (AJ_GUID));
        status = AJ_SetLocalGUID(guid);
    }

    return status;
}

AJ_Status AJ_SetLocalGUID(AJ_GUID* guid)
{
    AJ_InfoPrintf(("AJ_SetLocalGUID(guid=%p)\n", guid));
    return AJ_SetLocal(AJ_LOCAL_GUID_NV_ID, (uint8_t*) guid, sizeof (AJ_GUID));
}

AJ_Status AJ_CredentialExpired(AJ_Cred* cred)
{
    AJ_Time now;

    AJ_InitTimer(&now);
    if (now.seconds == 0) {
        /* don't know the current time so can't check the credential expriy */
        return AJ_ERR_INVALID;
    }

    if (cred->body.expiration > now.seconds) {
        return AJ_OK;
    }

    return AJ_ERR_KEY_EXPIRED; /* expires */
}

AJ_Status AJ_StoreCredential(AJ_Cred* cred)
{
    AJ_Status status = AJ_OK;
    uint16_t slot;
    uint32_t len;

    AJ_InfoPrintf(("AJ_StoreCredential(cred=%p)\n", cred));

    if (!cred) {
        return AJ_ERR_FAILURE;
    }

    slot = FindCredential(&cred->head, NULL, AJ_CREDS_NV_ID_BEGIN);
    if (!slot) {
        /*
         * Check there is sufficient space left.
         * If there isn't, keep deleting oldest credential until there is.
         */
        len = CredentialSize(cred);
        len = WORD_ALIGN(len);
        slot = FindCredsEmptySlot();
        while ((AJ_OK == status) && (!slot || (len >= AJ_NVRAM_GetSizeRemaining()))) {
            AJ_InfoPrintf(("AJ_StoreCredential(cred=%p): Remaining %d Required %d Slot %d\n", cred, AJ_NVRAM_GetSizeRemaining(), len, slot));
            slot = DeleteOldestCredential();
        }
    }

    if (slot) {
        status = AJ_SetCredential(cred, slot);
    } else {
        status = AJ_ERR_FAILURE;
    }

    return status;
}
