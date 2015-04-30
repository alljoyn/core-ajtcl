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

static uint16_t FindCredentialData(const AJ_Cred* cred)
{
    AJ_Status status;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;
    AJ_CredHead head;
    AJ_CredBody body;
    AJ_NV_DATASET* handle;

    for (; slot < AJ_CREDS_NV_ID_END; slot++) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        handle = AJ_NVRAM_Open(slot, "r", 0);
        if (!handle) {
            return 0;
        }
        status = CredHeadGet(&head, handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            return 0;
        }
        if (cred->head.type != head.type) {
            AJ_CredHeadFree(&head);
            AJ_NVRAM_Close(handle);
            continue;
        }
        AJ_CredHeadFree(&head);
        status = CredBodyGet(&body, handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            return 0;
        }
        if (cred->body.data.size != body.data.size) {
            AJ_CredBodyFree(&body);
            AJ_NVRAM_Close(handle);
            continue;
        }
        if (0 != memcmp(cred->body.data.data, body.data.data, body.data.size)) {
            AJ_CredBodyFree(&body);
            AJ_NVRAM_Close(handle);
            continue;
        }
        /* Found */
        AJ_CredBodyFree(&body);
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

AJ_Status AJ_KeyInfoGet(AJ_KeyInfo* key, uint16_t type, const AJ_GUID* guid)
{
    AJ_Status status;
    AJ_CredHead head;
    AJ_CredBody body;

    memset(key, 0, sizeof (AJ_KeyInfo));
    head.type = type | AJ_CRED_TYPE_KEYINFO;
    head.id.size = sizeof (AJ_GUID);
    head.id.data = (uint8_t*) guid->val;
    status = AJ_GetCredential(&head, &body);
    if (AJ_OK == status) {
        status = AJ_KeyInfoDeserialize(key, type, body.data.data, body.data.size);
        AJ_CredBodyFree(&body);
    }

    return status;
}

AJ_Status AJ_KeyInfoSet(const AJ_KeyInfo* key, uint16_t type, const AJ_GUID* guid)
{
    AJ_Status status;
    AJ_Cred cred;
    uint8_t* b8;
    size_t b8len;

    switch (type) {
    case AJ_KEYINFO_ECDSA_CA_PUB:
    case AJ_KEYINFO_ECDSA_SIG_PUB:
        b8len = KEYINFO_PUB_SZ;
        break;

    case AJ_KEYINFO_ECDSA_CA_PRV:
    case AJ_KEYINFO_ECDSA_SIG_PRV:
        b8len = KEYINFO_PRV_SZ;
        break;

    default:
        return AJ_ERR_INVALID;
    }

    b8 = AJ_Malloc(b8len);
    if (!b8) {
        return AJ_ERR_RESOURCES;
    }

    AJ_KeyInfoSerialize(key, type, b8, b8len);
    cred.head.type = type | AJ_CRED_TYPE_KEYINFO;
    cred.head.id.size = sizeof (AJ_GUID);
    cred.head.id.data = (uint8_t*) guid->val;
    cred.body.expiration = 0xFFFFFFFF;
    cred.body.association.size = 0;
    cred.body.association.data = NULL;
    cred.body.data.size = b8len;
    cred.body.data.data = b8;

    status = AJ_StoreCredential(&cred);
    AJ_Free(b8);

    return status;
}

AJ_Status AJ_KeyInfoGetLocal(AJ_KeyInfo* key, uint16_t type)
{
    AJ_Status status;
    AJ_GUID guid;

    status = AJ_GetLocalGUID(&guid);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_KeyInfoGet(key, type, &guid);

    return status;
}

AJ_Status AJ_KeyInfoSetLocal(const AJ_KeyInfo* key, uint16_t type)
{
    AJ_Status status;
    AJ_GUID guid;

    status = AJ_GetLocalGUID(&guid);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_KeyInfoSet(key, type, &guid);

    return status;
}

AJ_Status AJ_KeyInfoSerialize(const AJ_KeyInfo* key, uint16_t type, uint8_t* b8, size_t len)
{
    AJ_Status status = AJ_ERR_INVALID;

    if ((NULL == key) || (NULL == b8)) {
        return AJ_ERR_INVALID;
    }

    if (len < (5 + sizeof (AJ_GUID))) {
        return AJ_ERR_RESOURCES;
    }
    *b8++ = key->fmt;
    memcpy(b8, key->kid, sizeof (AJ_GUID));
    b8 += sizeof (AJ_GUID);
    *b8++ = key->use;
    *b8++ = key->kty;
    *b8++ = key->alg;
    *b8++ = key->crv;
    switch (type) {
    case AJ_KEYINFO_ECDSA_CA_PUB:
    case AJ_KEYINFO_ECDSA_SIG_PUB:
        if (len < KEYINFO_PUB_SZ) {
            return AJ_ERR_RESOURCES;
        }
        AJ_BigvalEncode(&key->key.publickey.x, b8, KEY_ECC_SZ);
        b8 += KEY_ECC_SZ;
        AJ_BigvalEncode(&key->key.publickey.y, b8, KEY_ECC_SZ);
        b8 += KEY_ECC_SZ;
        status = AJ_OK;
        break;

    case AJ_KEYINFO_ECDSA_CA_PRV:
    case AJ_KEYINFO_ECDSA_SIG_PRV:
        if (len < KEYINFO_PRV_SZ) {
            return AJ_ERR_RESOURCES;
        }
        AJ_BigvalEncode(&key->key.privatekey, b8, KEY_ECC_SZ);
        b8 += KEY_ECC_SZ;
        status = AJ_OK;
        break;
    }

    return status;
}

AJ_Status AJ_KeyInfoDeserialize(AJ_KeyInfo* key, uint16_t type, const uint8_t* b8, size_t len)
{
    AJ_Status status = AJ_ERR_INVALID;

    if ((NULL == key) || (NULL == b8)) {
        return AJ_ERR_INVALID;
    }

    if (len < (5 + sizeof (AJ_GUID))) {
        return AJ_ERR_RESOURCES;
    }
    key->fmt = *b8++;
    memcpy(key->kid, b8, sizeof (AJ_GUID));
    b8 += sizeof (AJ_GUID);
    key->use = *b8++;
    key->kty = *b8++;
    key->alg = *b8++;
    key->crv = *b8++;
    switch (type) {
    case AJ_KEYINFO_ECDSA_CA_PUB:
    case AJ_KEYINFO_ECDSA_SIG_PUB:
        if (len < KEYINFO_PUB_SZ) {
            return AJ_ERR_RESOURCES;
        }
        AJ_BigvalDecode(b8, &key->key.publickey.x, KEY_ECC_SZ);
        b8 += KEY_ECC_SZ;
        AJ_BigvalDecode(b8, &key->key.publickey.y, KEY_ECC_SZ);
        b8 += KEY_ECC_SZ;
        status = AJ_OK;
        break;

    case AJ_KEYINFO_ECDSA_CA_PRV:
    case AJ_KEYINFO_ECDSA_SIG_PRV:
        if (len < KEYINFO_PRV_SZ) {
            return AJ_ERR_RESOURCES;
        }
        AJ_BigvalDecode(b8, &key->key.privatekey, KEY_ECC_SZ);
        b8 += KEY_ECC_SZ;
        status = AJ_OK;
        break;
    }

    return status;
}

AJ_Status AJ_KeyInfoMarshal(const AJ_KeyInfo* key, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    uint8_t x[KEY_ECC_SZ];
    uint8_t y[KEY_ECC_SZ];

    AJ_BigvalEncode(&key->key.publickey.x, x, KEY_ECC_SZ);
    AJ_BigvalEncode(&key->key.publickey.y, y, KEY_ECC_SZ);
    if (hash) {
        AJ_SHA256_Update(hash, x, KEY_ECC_SZ);
        AJ_SHA256_Update(hash, y, KEY_ECC_SZ);
    }

    status = AJ_MarshalArgs(msg,
                            "(yv)", key->fmt,
                            "(ayyyv)", (uint8_t*) key->kid, sizeof (AJ_GUID), key->use, key->kty,
                            "(yyv)", key->alg, key->crv,
                            "(ayay)", x, KEY_ECC_SZ, y, KEY_ECC_SZ);

    return status;
}

static AJ_Status AJ_KeyInfoUnmarshalCrv(AJ_KeyInfo* key, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status;
    uint8_t* x;
    uint8_t* y;
    size_t xlen;
    size_t ylen;

    status = AJ_UnmarshalArgs(msg, "(ayay)", &x, &xlen, &y, &ylen);
    if (AJ_OK != status) {
        return status;
    }
    if ((KEY_ECC_SZ != xlen) || (KEY_ECC_SZ != ylen)) {
        return AJ_ERR_INVALID;
    }
    AJ_BigvalDecode(x, &key->key.publickey.x, KEY_ECC_SZ);
    AJ_BigvalDecode(y, &key->key.publickey.y, KEY_ECC_SZ);
    if (hash) {
        AJ_SHA256_Update(hash, x, KEY_ECC_SZ);
        AJ_SHA256_Update(hash, y, KEY_ECC_SZ);
    }

    return status;
}

static AJ_Status AJ_KeyInfoUnmarshalTyp(AJ_KeyInfo* key, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    AJ_Arg container;
    char* variant;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "yy", &key->alg, &key->crv);
    if (KEY_ALG_ECDSA_SHA256 != key->alg) {
        return AJ_ERR_INVALID;
    }
    if (KEY_CRV_NISTP256 != key->crv) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(ayay)", 6)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_KeyInfoUnmarshalCrv(key, msg, hash);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}

static AJ_Status AJ_KeyInfoUnmarshalFmt(AJ_KeyInfo* key, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    AJ_Arg container;
    char* variant;
    uint8_t* kid;
    size_t kidlen;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "ayyy", &kid, &kidlen, &key->use, &key->kty);
    if (KEY_TYP_ECC != key->kty) {
        return AJ_ERR_INVALID;
    }
    //TODO: are we requiring kid length to be sizeof GUID?
    if (sizeof (AJ_GUID) < kidlen) {
        return AJ_ERR_INVALID;
    }
    memcpy(key->kid, kid, kidlen);
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(yyv)", 5)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_KeyInfoUnmarshalTyp(key, msg, hash);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}

AJ_Status AJ_KeyInfoUnmarshal(AJ_KeyInfo* key, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    AJ_Arg container;
    char* variant;

    memset(key, 0, sizeof (AJ_KeyInfo));
    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "y", &key->fmt);
    if (AJ_OK != status) {
        return status;
    }
    if (KEY_FMT_ALLJOYN != key->fmt) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(ayyyv)", 7)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_KeyInfoUnmarshalFmt(key, msg, hash);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}

AJ_Status AJ_KeyInfoGenerate(AJ_KeyInfo* pub, AJ_KeyInfo* prv, uint8_t use)
{
    AJ_Status status;
    AJ_GUID guid;

    AJ_InfoPrintf(("AJ_KeyInfoGenerate(pub=%p, prv=%p, use=%x)\n", pub, prv, use));

    memset(pub, 0, sizeof (AJ_KeyInfo));
    memset(prv, 0, sizeof (AJ_KeyInfo));

    status = AJ_GetLocalGUID(&guid);
    if (AJ_OK != status) {
        return status;
    }
    memcpy(pub->kid, (uint8_t*) &guid, sizeof (AJ_GUID));
    memcpy(prv->kid, (uint8_t*) &guid, sizeof (AJ_GUID));

    pub->fmt = KEY_FMT_ALLJOYN;
    pub->use = use;
    pub->kty = KEY_TYP_ECC;
    pub->alg = KEY_ALG_ECDSA_SHA256;
    pub->crv = KEY_CRV_NISTP256;

    prv->fmt = KEY_FMT_ALLJOYN;
    prv->use = use;
    prv->kty = KEY_TYP_ECC;
    prv->alg = KEY_ALG_ECDSA_SHA256;
    prv->crv = KEY_CRV_NISTP256;

    status = AJ_GenerateECDSAKeyPair(&pub->key.publickey, &prv->key.privatekey);

    return status;
}

AJ_Status AJ_SigInfoSerialize(const AJ_SigInfo* sig, uint8_t* b8, size_t len)
{
    size_t req = SIG_INFO_SZ;

    if ((NULL == sig) || (NULL == b8)) {
        return AJ_ERR_INVALID;
    }
    if (len < req) {
        return AJ_ERR_INVALID;
    }
    *b8++ = sig->fmt;
    *b8++ = sig->alg;
    AJ_BigvalEncode(&sig->signature.r, b8, KEY_ECC_SZ);
    b8 += KEY_ECC_SZ;
    AJ_BigvalEncode(&sig->signature.s, b8, KEY_ECC_SZ);
    b8 += KEY_ECC_SZ;

    return AJ_OK;
}

AJ_Status AJ_SigInfoDeserialize(AJ_SigInfo* sig, const uint8_t* b8, size_t len)
{
    size_t req = SIG_INFO_SZ;

    if ((NULL == sig) || (NULL == b8)) {
        return AJ_ERR_INVALID;
    }
    if (len < req) {
        return AJ_ERR_INVALID;
    }
    sig->fmt = *b8++;
    sig->alg = *b8++;
    AJ_BigvalDecode(b8, &sig->signature.r, KEY_ECC_SZ);
    b8 += KEY_ECC_SZ;
    AJ_BigvalDecode(b8, &sig->signature.s, KEY_ECC_SZ);
    b8 += KEY_ECC_SZ;

    return AJ_OK;
}

AJ_Status AJ_SigInfoMarshal(const AJ_SigInfo* sig, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    uint8_t r[KEY_ECC_SZ];
    uint8_t s[KEY_ECC_SZ];

    AJ_BigvalEncode(&sig->signature.r, r, KEY_ECC_SZ);
    AJ_BigvalEncode(&sig->signature.s, s, KEY_ECC_SZ);
    if (hash) {
        AJ_SHA256_Update(hash, r, KEY_ECC_SZ);
        AJ_SHA256_Update(hash, s, KEY_ECC_SZ);
    }

    status = AJ_MarshalArgs(msg,
                            "yv", sig->fmt,
                            "(yv)", sig->alg,
                            "(ayay)", r, KEY_ECC_SZ, s, KEY_ECC_SZ);

    return status;
}

static AJ_Status AJ_SigInfoUnmarshalAlg(AJ_SigInfo* sig, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    uint8_t* r;
    uint8_t* s;
    size_t rlen;
    size_t slen;

    status = AJ_UnmarshalArgs(msg, "(ayay)", &r, &rlen, &s, &slen);
    if (AJ_OK != status) {
        return status;
    }
    if ((KEY_ECC_SZ != rlen) || (KEY_ECC_SZ != slen)) {
        return AJ_ERR_INVALID;
    }
    AJ_BigvalDecode(r, &sig->signature.r, KEY_ECC_SZ);
    AJ_BigvalDecode(s, &sig->signature.s, KEY_ECC_SZ);
    if (hash) {
        AJ_SHA256_Update(hash, r, KEY_ECC_SZ);
        AJ_SHA256_Update(hash, s, KEY_ECC_SZ);
    }

    return status;
}

static AJ_Status AJ_SigInfoUnmarshalFmt(AJ_SigInfo* sig, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    AJ_Arg container;
    char* variant;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "y", &sig->alg);
    if (SIG_ALG_ECDSA_SHA256 != sig->alg) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(ayay)", 6)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_SigInfoUnmarshalAlg(sig, msg, hash);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}

AJ_Status AJ_SigInfoUnmarshal(AJ_SigInfo* sig, AJ_Message* msg, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_ERR_INVALID;
    char* variant;

    memset(sig, 0, sizeof (AJ_SigInfo));
    status = AJ_UnmarshalArgs(msg, "y", &sig->fmt);
    if (AJ_OK != status) {
        return status;
    }
    if (KEY_FMT_ALLJOYN != sig->fmt) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(yv)", 4)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_SigInfoUnmarshalFmt(sig, msg, hash);

    return status;
}

AJ_Status AJ_TrustAnchorsMarshal(AJ_Message* msg, uint8_t found, AJ_SHA256_Context* hash)
{
    AJ_Status status;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;
    AJ_CredHead head;
    AJ_CredBody body;
    AJ_NV_DATASET* handle;
    AJ_Arg container;
    AJ_KeyInfo pub;

    AJ_InfoPrintf(("AJ_TrustAnchorsMarshal(msg=%p)\n", msg));

    status = AJ_MarshalVariant(msg, "a(yv)");
    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);

    /*
     * If trust anchors were found on the other side, send ours.
     * Otherwise, send an empty array.
     * If we can't mutually authenticate, we don't want them to try.
     */
    if (found) {
        for (; slot < AJ_CREDS_NV_ID_END; slot++) {
            if (!AJ_NVRAM_Exist(slot)) {
                continue;
            }
            handle = AJ_NVRAM_Open(slot, "r", 0);
            if (!handle) {
                return AJ_ERR_FAILURE;
            }
            status = CredHeadGet(&head, handle);
            if (AJ_OK != status) {
                AJ_NVRAM_Close(handle);
                return AJ_ERR_FAILURE;
            }
            if ((AJ_KEYINFO_ECDSA_CA_PUB | AJ_CRED_TYPE_KEYINFO) != head.type) {
                AJ_CredHeadFree(&head);
                AJ_NVRAM_Close(handle);
                continue;
            }
            AJ_CredHeadFree(&head);
            status = CredBodyGet(&body, handle);
            if (AJ_OK != status) {
                AJ_NVRAM_Close(handle);
                return AJ_ERR_FAILURE;
            }
            status = AJ_KeyInfoDeserialize(&pub, AJ_KEYINFO_ECDSA_CA_PUB, body.data.data, body.data.size);
            AJ_CredBodyFree(&body);
            if (AJ_OK != status) {
                AJ_NVRAM_Close(handle);
                return AJ_ERR_FAILURE;
            }
            status = AJ_KeyInfoMarshal(&pub, msg, hash);
            AJ_NVRAM_Close(handle);
            if (AJ_OK != status) {
                return status;
            }
        }
    }

    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

AJ_Status AJ_TrustAnchorsUnmarshal(AJ_Message* msg, uint8_t* found, AJ_GUID* ta, AJ_SHA256_Context* hash)
{
    AJ_Status status;
    char* variant;
    AJ_Arg container;
    AJ_Cred cred;
    AJ_KeyInfo pub;
    uint8_t b8[KEYINFO_PUB_SZ];

    AJ_InfoPrintf(("AJ_TrustAnchorsUnmarshal(msg=%p)\n", msg));

    *found = 0;
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "a(yv)", 5)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = AJ_KeyInfoUnmarshal(&pub, msg, hash);
        if (AJ_OK != status) {
            break;
        }
        /*
         * See if I have a trust anchor the same.
         * This should really check for a matching certificate
         * (one that is signed by their trust anchor).
         * Assumption at the moment is that our certificate issuers
         * are also our trust anchors.
         */
        status = AJ_KeyInfoSerialize(&pub, AJ_KEYINFO_ECDSA_CA_PUB, b8, sizeof (b8));
        if (AJ_OK != status) {
            break;
        }
        cred.head.type = AJ_KEYINFO_ECDSA_CA_PUB | AJ_CRED_TYPE_KEYINFO;
        cred.head.id.data = NULL;
        cred.head.id.size = 0;
        cred.body.data.data = b8;
        cred.body.data.size = sizeof (b8);
        if (FindCredentialData(&cred)) {
            AJ_InfoPrintf(("AJ_TrustAnchorsUnmarshal(msg=%p, found=%p): Trust anchor found\n", msg, found));
            AJ_DumpBytes("TA", b8, sizeof (b8));
            *found = 1;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}

AJ_Status AJ_CredBodyMarshal(AJ_CredBody* body, AJ_Message* msg)
{
    uint16_t size = body->data.size;

    if (size > AJ_IO_BUF_SPACE(&msg->bus->sock.tx)) {
        return AJ_ERR_RESOURCES;
    }
    msg->hdr->bodyLen += size;
    msg->bodyBytes += size;
    /*
     * Copy the data straight into the tx buffer
     */
    memcpy(msg->bus->sock.tx.writePtr, body->data.data, size);
    msg->bus->sock.tx.writePtr += size;

    return AJ_OK;
}

AJ_Status AJ_GetMembershipAuthData(uint16_t slot, AJ_CredBody* body)
{
    AJ_Status status;
    AJ_CredHead head;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_GetMembershipAuthData(slot=%d, body=%p)\n", slot, body));

    /*
     * Check for optional auth data.
     * Read the id out of the slot from the current membership certificate.
     * Assumption is that the slot contents have not changed in the meantime.
     */
    if (!AJ_NVRAM_Exist(slot)) {
        return AJ_ERR_INVALID;
    }
    handle = AJ_NVRAM_Open(slot, "r", 0);
    if (!handle) {
        return AJ_ERR_FAILURE;
    }
    status = CredHeadGet(&head, handle);
    if (AJ_OK != status) {
        AJ_NVRAM_Close(handle);
        return AJ_ERR_FAILURE;
    }
    head.type = AJ_POLICY_MEMBERSHIP | AJ_CRED_TYPE_POLICY;
    status = AJ_GetCredential(&head, body);
    AJ_CredHeadFree(&head);

    return status;
}

AJ_Status AJ_AuthDataUnmarshal(AJ_Message* msg)
{
    AJ_Status status;
    char* variant;
    AJ_Arg container;
    AJ_AuthRecord record;

    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "a(yv)", 5)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = AJ_AuthRecordUnmarshal(&record, msg);
        if (AJ_OK != status) {
            break;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}
