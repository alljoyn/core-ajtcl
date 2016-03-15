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

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_status.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_crypto_sha2.h>
#include <ajtcl/aj_cert.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCREDS = 0;
#endif

static AJ_Status CredValueRead(uint8_t* data, size_t size, AJ_NV_DATASET* handle)
{
    return (size == AJ_NVRAM_Read(data, size, handle)) ? AJ_OK : AJ_ERR_FAILURE;
}

static AJ_Status CredValueWrite(const uint8_t* data, size_t size, AJ_NV_DATASET* handle)
{
    return (size == AJ_NVRAM_Write(data, size, handle)) ? AJ_OK : AJ_ERR_FAILURE;
}

/**
 * If a data buffer exists in the input field,
 * the contents will be written straight to that buffer.
 * Its size taken into account.
 * If no data buffer exists in the input field,
 * a new buffer will be allocated and the contents written to it.
 * The caller must be aware, so they know whether to free it.
 */
static AJ_Status CredFieldRead(AJ_CredField* field, AJ_NV_DATASET* handle)
{
    uint16_t size;

    /* Read size */
    if (sizeof (uint16_t) != AJ_NVRAM_Read((uint8_t*) &size, sizeof (uint16_t), handle)) {
        return AJ_ERR_FAILURE;
    }

    /* If no data to read, return */
    if (0 == size) {
        field->size = 0;
        return AJ_OK;
    }

    if (NULL == field->data) {
        /* If field->data not passed in, allocate memory for it */
        field->size = 0;
        field->data = (uint8_t*) AJ_Malloc(size);
        if (NULL != field->data) {
            field->size = size;
        }
    }

    /* Check sufficient buffer */
    if (field->size < size) {
        return AJ_ERR_RESOURCES;
    }

    /* Read data */
    if (size != AJ_NVRAM_Read(field->data, size, handle)) {
        return AJ_ERR_FAILURE;
    }
    field->size = size;

    return AJ_OK;
}

static AJ_Status CredFieldWrite(const AJ_CredField* field, AJ_NV_DATASET* handle)
{
    uint16_t size = 0;

    if (NULL != field) {
        size = field->size;
    }

    /* Write size */
    if (sizeof (uint16_t) != AJ_NVRAM_Write((uint8_t*) &size, sizeof (uint16_t), handle)) {
        return AJ_ERR_FAILURE;
    }

    /* If no data to write, return */
    if (0 == size) {
        return AJ_OK;
    }

    /* Write data */
    if (field->size != AJ_NVRAM_Write((uint8_t*) field->data, field->size, handle)) {
        return AJ_ERR_FAILURE;
    }

    return AJ_OK;
}

static uint16_t CredentialSize(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_CredField* data)
{
    uint16_t size = sizeof (type) + sizeof (id->size) + sizeof (data->size) + sizeof (expiration);
    if (id) {
        size += id->size;
    }
    if (data) {
        size += data->size;
    }
    return size;
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

static uint16_t CredentialFind(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_CredField* data, uint16_t slot)
{
    AJ_Status status;
    AJ_NV_DATASET* handle;
    uint32_t exp;
    uint16_t value;
    AJ_CredField field;
    uint8_t found;

    for (; slot < AJ_CREDS_NV_ID_END; slot++) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        handle = AJ_NVRAM_Open(slot, "r", 0);
        if (!handle) {
            continue;
        }
        /* Read type */
        status = CredValueRead((uint8_t*) &value, sizeof (uint16_t), handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            return 0;
        }
        /* Compare type */
        if (value != type) {
            AJ_NVRAM_Close(handle);
            continue;
        }
        if ((NULL == id) && (NULL == expiration) && (NULL == data)) {
            /* No more fields requested */
            AJ_NVRAM_Close(handle);
            return slot;
        }
        /* Read id */
        field.data = NULL;
        status = CredFieldRead(&field, handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            return 0;
        }
        /* Compare id */
        found = 1;
        if (id) {
            if ((field.size != id->size) || (0 != memcmp(field.data, id->data, field.size))) {
                found = 0;
            }
        }
        AJ_CredFieldFree(&field);
        if (!found) {
            AJ_NVRAM_Close(handle);
            continue;
        }
        if ((NULL == expiration) && (NULL == data)) {
            /* No more fields requested */
            AJ_NVRAM_Close(handle);
            return slot;
        }
        status = CredValueRead((uint8_t*) &exp, sizeof (uint32_t), handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            return 0;
        }
        if (expiration) {
            *expiration = exp;
        }
        if (NULL == data) {
            /* No more fields requested */
            AJ_NVRAM_Close(handle);
            return slot;
        }
        status = CredFieldRead(data, handle);
        AJ_NVRAM_Close(handle);
        if (AJ_OK != status) {
            return 0;
        }
        return slot;
    }

    return 0; /* not found */
}

static AJ_Status DeleteOldestCredential(uint16_t* deleted)
{
    AJ_Status status = AJ_ERR_INVALID;
    AJ_NV_DATASET* handle;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;
    uint16_t oldestslot = 0;
    uint32_t oldestexp = 0xFFFFFFFF;
    uint16_t type;
    AJ_CredField id;
    uint32_t expiration;

    AJ_InfoPrintf(("DeleteOldestCredential(deleted=%p)\n", deleted));

    for (; slot < AJ_CREDS_NV_ID_END; slot++) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        handle = AJ_NVRAM_Open(slot, "r", 0);
        if (!handle) {
            continue;
        }
        status = CredValueRead((uint8_t*) &type, sizeof (uint16_t), handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            continue;
        }
        if (AJ_CRED_TYPE_GENERIC != type) {
            AJ_NVRAM_Close(handle);
            continue;
        }
        /* Read id */
        id.size = 0;
        id.data = NULL;
        status = CredFieldRead(&id, handle);
        AJ_CredFieldFree(&id);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            continue;
        }
        status = CredValueRead((uint8_t*) &expiration, sizeof (uint32_t), handle);
        if (AJ_OK != status) {
            AJ_NVRAM_Close(handle);
            continue;
        }
        /* If older */
        if (expiration <= oldestexp) {
            oldestexp = expiration;
            oldestslot = slot;
        }
    }

    if (oldestslot) {
        AJ_InfoPrintf(("DeleteOldestCredential(deleted=%p): slot=%d exp=%08X\n", deleted, oldestslot, oldestexp));
        status = AJ_CredentialDeleteSlot(type, oldestslot);
        if (AJ_OK != status) {
            AJ_ErrPrintf(("AJ_CredentialDeleteSlot() failed, status=%s\n", AJ_StatusText(status)));
        } else {
            *deleted = oldestslot;
        }
        return status;
    }

    return AJ_ERR_UNKNOWN;
}

static AJ_Status CredentialWrite(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_CredField* data, uint16_t slot)
{
    AJ_Status status = AJ_OK;
    AJ_NV_DATASET* handle;
    size_t size;

    AJ_InfoPrintf(("CredentialWrite(type=%04x, id=%p, expiration=%08x, data=%p, slot=%d)\n", type, id, expiration, data, slot));

    size = CredentialSize(type, id, expiration, data);
    handle = AJ_NVRAM_Open(slot, "w", size);
    if (!handle) {
        return AJ_ERR_FAILURE;
    }
    status = CredValueWrite((uint8_t*) &type, sizeof (uint16_t), handle);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = CredFieldWrite(id, handle);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = CredValueWrite((uint8_t*) &expiration, sizeof (uint32_t), handle);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = CredFieldWrite(data, handle);
    if (AJ_OK != status) {
        goto Exit;
    }

Exit:
    AJ_NVRAM_Close(handle);

    return status;
}

AJ_Status AJ_CredentialRead(uint16_t* type, AJ_CredField* id, uint32_t* expiration, AJ_CredField* data, uint16_t slot)
{
    AJ_Status status;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_CredentialRead(type=%p, id=%p, expiration=%p, data=%p, slot=%d)\n", type, id, expiration, data, slot));

    handle = AJ_NVRAM_Open(slot, "r", 0);
    if (!handle) {
        return AJ_ERR_FAILURE;
    }
    status = CredValueRead((uint8_t*) type, sizeof (uint16_t), handle);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = CredFieldRead(id, handle);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = CredValueRead((uint8_t*) expiration, sizeof (uint32_t), handle);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = CredFieldRead(data, handle);
    if (AJ_OK != status) {
        goto Exit;
    }

Exit:
    AJ_NVRAM_Close(handle);

    return status;
}

AJ_Status AJ_CredentialSet(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_CredField* data)
{
    AJ_Status status = AJ_OK;
    uint16_t slot;
    uint32_t size;

    AJ_InfoPrintf(("AJ_CredentialSet(type=%04x, id=%p, expiration=%08x, data=%p)\n", type, id, expiration, data));

    slot = CredentialFind(type, id, NULL, NULL, AJ_CREDS_NV_ID_BEGIN);
    if (!slot) {
        /*
         * Check there is sufficient space left.
         * If there isn't, keep deleting oldest credential until there is.
         */
        size = CredentialSize(type, id, expiration, data);
        size = WORD_ALIGN(size);
        slot = FindCredsEmptySlot();
        while ((AJ_OK == status) && (!slot || (size >= AJ_NVRAM_GetSizeRemaining()))) {
            status = DeleteOldestCredential(&slot);
        }
    }

    if (slot) {
        status = CredentialWrite(type, id, expiration, data, slot);
    } else {
        status = AJ_ERR_FAILURE;
    }

    return status;
}

AJ_Status AJ_CredentialGet(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_CredField* data)
{
    AJ_InfoPrintf(("AJ_CredentialGet(type=%04x, id=%p, expiration=%p, data=%p)\n", type, id, expiration, data));
    return CredentialFind(type, id, expiration, data, AJ_CREDS_NV_ID_BEGIN) ? AJ_OK : AJ_ERR_UNKNOWN;
}

AJ_Status AJ_CredentialGetNext(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_CredField* data, uint16_t* slot)
{
    AJ_InfoPrintf(("AJ_CredentialGet(type=%04x, id=%p, expiration=%p, data=%p)\n", type, id, expiration, data));
    *slot = CredentialFind(type, id, expiration, data, *slot);
    return *slot ? AJ_OK : AJ_ERR_UNKNOWN;
}

static AJ_Status CredentialSetLocal(uint16_t slot, const uint8_t* data, uint16_t size)
{
    AJ_Status status;
    AJ_NV_DATASET* handle;

    handle = AJ_NVRAM_Open(slot, "w", size);
    if (!handle) {
        AJ_WarnPrintf(("CredentialSetLocal(slot=%d, data=%p, size=%d): Error opening slot\n", slot, data, size));
        return AJ_ERR_FAILURE;
    }
    if (size == AJ_NVRAM_Write(data, size, handle)) {
        status = AJ_OK;
    } else {
        AJ_WarnPrintf(("CredentialSetLocal(slot=%d, data=%p, size=%d): Error writing slot\n", slot, data, size));
        status = AJ_ERR_FAILURE;
    }
    AJ_NVRAM_Close(handle);

    return status;
}

static AJ_Status CredentialGetLocal(uint16_t slot, uint8_t* data, uint16_t size)
{
    AJ_Status status;
    AJ_NV_DATASET* handle;

    if (!AJ_NVRAM_Exist(slot)) {
        return AJ_ERR_FAILURE;
    }
    handle = AJ_NVRAM_Open(slot, "r", 0);
    if (!handle) {
        AJ_WarnPrintf(("CredentialGetLocal(slot=%d, data=%p, size=%d): Error opening slot\n", slot, data, size));
        return AJ_ERR_FAILURE;
    }
    if (size == AJ_NVRAM_Read(data, size, handle)) {
        status = AJ_OK;
    } else {
        AJ_WarnPrintf(("CredentialGetLocal(slot=%d, data=%p, size=%d): Error reading slot\n", slot, data, size));
        status = AJ_ERR_FAILURE;
    }
    AJ_NVRAM_Close(handle);

    return status;
}

static AJ_Status CredentialSetGUID(AJ_GUID* guid)
{
    AJ_InfoPrintf(("CredentialSetGUID(guid=%p)\n", guid));
    return CredentialSetLocal(AJ_LOCAL_GUID_NV_ID, (uint8_t*) guid, sizeof (AJ_GUID));
}

AJ_Status AJ_GetLocalGUID(AJ_GUID* guid)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_GetLocalGUID(guid=%p)\n", guid));

    status = CredentialGetLocal(AJ_LOCAL_GUID_NV_ID, (uint8_t*) guid, sizeof (AJ_GUID));
    if (AJ_OK != status) {
        AJ_RandBytes((uint8_t*) guid, sizeof (AJ_GUID));
        status = CredentialSetGUID(guid);
    }

    return status;
}

AJ_Status AJ_CredentialSetPeer(uint16_t type, const AJ_GUID* guid, uint32_t expiration, const uint8_t* secret, uint16_t size)
{
    AJ_CredField id;
    AJ_CredField data;
    AJ_Status status;

    AJ_InfoPrintf(("AJ_CredentialSetPeer(guid=%p, expiration=%08X, secret=%p, size=%d)\n", guid, expiration, secret, size));

    id.size = sizeof (AJ_GUID);
    id.data = (uint8_t*) guid;
    data.size = size;
    data.data = (uint8_t*) secret;
    status = AJ_CredentialSet(type | AJ_CRED_TYPE_GENERIC, &id, expiration, &data);

    return status;
}

AJ_Status AJ_CredentialGetPeer(uint16_t type, const AJ_GUID* guid, uint32_t* expiration, AJ_CredField* data)
{
    AJ_CredField id;

    id.size = sizeof (AJ_GUID);
    id.data = (uint8_t*) guid;

    return AJ_CredentialGet(type | AJ_CRED_TYPE_GENERIC, &id, expiration, data);
}

AJ_Status AJ_CredentialSetECCPublicKey(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_ECCPublicKey* pub)
{
    AJ_CredField data;

    data.size = sizeof (AJ_ECCPublicKey);
    data.data = (uint8_t*) pub;

    return AJ_CredentialSet(type | AJ_CRED_TYPE_PUBLIC, id, expiration, &data);
}

AJ_Status AJ_CredentialGetECCPublicKey(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_ECCPublicKey* pub)
{
    AJ_CredField data;

    data.size = sizeof (AJ_ECCPublicKey);
    data.data = (uint8_t*) pub;

    return AJ_CredentialGet(type | AJ_CRED_TYPE_PUBLIC, id, NULL, &data);
}

AJ_Status AJ_CredentialSetECCPrivateKey(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_ECCPrivateKey* prv)
{
    AJ_CredField data;

    data.size = sizeof (AJ_ECCPrivateKey);
    data.data = (uint8_t*) prv;

    return AJ_CredentialSet(type | AJ_CRED_TYPE_PRIVATE, id, expiration, &data);
}

AJ_Status AJ_CredentialGetECCPrivateKey(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_ECCPrivateKey* prv)
{
    AJ_CredField data;

    data.size = sizeof (AJ_ECCPrivateKey);
    data.data = (uint8_t*) prv;

    return AJ_CredentialGet(type | AJ_CRED_TYPE_PRIVATE, id, NULL, &data);
}

AJ_Status AJ_CredentialDeleteSlot(uint16_t type, uint16_t slot)
{
    AJ_Status status = AJ_ERR_FAILURE;
    if (slot > 0) {
        if ((type == AJ_CRED_TYPE_AES) ||
            (type == AJ_CRED_TYPE_PRIVATE) ||
            (type == AJ_GENERIC_MASTER_SECRET) ||
            (type == AJ_ECC_SIG)) {
            status = AJ_NVRAM_SecureDelete(slot);
        } else {
            status = AJ_NVRAM_Delete(slot);
        }
    }
    return status;
}

AJ_Status AJ_CredentialDelete(uint16_t type, const AJ_CredField* id)
{
    AJ_Status status = AJ_ERR_FAILURE;
    uint16_t slot = CredentialFind(type, id, NULL, NULL, AJ_CREDS_NV_ID_BEGIN);

    AJ_InfoPrintf(("AJ_CredentialDelete(type=%04x, id=%p)\n", type, id));
    status = AJ_CredentialDeleteSlot(type, slot);

    return status;
}

void AJ_CredentialDeletePeer(const AJ_GUID* guid)
{
    AJ_CredField id;

    id.size = sizeof (AJ_GUID);
    id.data = (uint8_t*) guid;
    AJ_CredentialDelete(AJ_GENERIC_MASTER_SECRET | AJ_CRED_TYPE_GENERIC, &id);
    AJ_CredentialDelete(AJ_GENERIC_ECDSA_THUMBPRINT | AJ_CRED_TYPE_GENERIC, &id);
    AJ_CredentialDelete(AJ_GENERIC_ECDSA_KEYS | AJ_CRED_TYPE_GENERIC, &id);
}

AJ_Status AJ_ClearCredentials(uint16_t type)
{
    AJ_Status status = AJ_OK;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;
    uint16_t test;
    AJ_NV_DATASET* handle;

    AJ_InfoPrintf(("AJ_ClearCredentials(type=%04x)\n", type));

    for (; slot < AJ_CREDS_NV_ID_END; ++slot) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        if (type) {
            handle = AJ_NVRAM_Open(slot, "r", 0);
            if (!handle) {
                AJ_WarnPrintf(("AJ_ClearCredentials(type=%04x): Error opening slot %d\n", type, slot));
                continue;
            }
            status = CredValueRead((uint8_t*) &test, sizeof (uint16_t), handle);
            if (AJ_OK != status) {
                AJ_WarnPrintf(("AJ_ClearCredentials(type=%04x): Error reading slot %d\n", type, slot));
                AJ_NVRAM_Close(handle);
                continue;
            }
            AJ_NVRAM_Close(handle);
            if (test != type) {
                continue;
            }
        }
        AJ_NVRAM_Delete(slot);
    }

    return status;
}

AJ_Status AJ_CredentialExpired(uint32_t expiration)
{
    AJ_Time now;

    AJ_InitTimer(&now);
    if (now.seconds == 0) {
        /* don't know the current time so can't check the credential expriy */
        return AJ_ERR_INVALID;
    }

    if (expiration > now.seconds) {
        return AJ_OK;
    }

    return AJ_ERR_KEY_EXPIRED; /* expires */
}

void AJ_CredFieldFree(AJ_CredField* field)
{
    if (field && field->data) {
        AJ_MemZeroSecure(field->data, field->size);
        AJ_Free(field->data);
        field->data = NULL;
    }
}
