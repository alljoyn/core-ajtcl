/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012, 2013, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE GUID

#include "aj_target.h"
#include "aj_guid.h"
#include "aj_util.h"
#include "aj_crypto.h"
#include "aj_debug.h"
#include "aj_config.h"
/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgGUID = 0;
#endif

typedef struct _NameToGUID {
    uint8_t keyRole;
    char uniqueName[AJ_MAX_NAME_SIZE + 1];
    const char* serviceName;
    AJ_GUID guid;
    uint8_t sessionKey[16];
    uint8_t groupKey[16];
} NameToGUID;

static uint8_t localGroupKey[16];

static NameToGUID nameMap[AJ_NAME_MAP_GUID_SIZE];

AJ_Status AJ_GUID_ToString(const AJ_GUID* guid, char* buffer, uint32_t bufLen)
{
    return AJ_RawToHex(guid->val, 16, buffer, bufLen, TRUE);
}

AJ_Status AJ_GUID_FromString(AJ_GUID* guid, const char* str)
{
    return AJ_HexToRaw(str, 32, guid->val, 16);
}

static NameToGUID* LookupName(const char* name)
{
    uint32_t i;
    AJ_InfoPrintf(("LookupName(name=\"%s\")\n", name));

    for (i = 0; i < AJ_NAME_MAP_GUID_SIZE; ++i) {
        if (strcmp(nameMap[i].uniqueName, name) == 0) {
            return &nameMap[i];
        }
        if (nameMap[i].serviceName && (strcmp(nameMap[i].serviceName, name)) == 0) {
            return &nameMap[i];
        }
    }
    AJ_WarnPrintf(("LookupName(): NULL\n"));
    return NULL;
}

AJ_Status AJ_GUID_AddNameMapping(const AJ_GUID* guid, const char* uniqueName, const char* serviceName)
{
    size_t len = strlen(uniqueName);
    NameToGUID* mapping;

    AJ_InfoPrintf(("AJ_GUID_AddNameMapping(guid=0x%p, uniqueName=\"%s\", serviceName=\"%s\")\n", guid, uniqueName, serviceName));

    mapping = LookupName(uniqueName);
    if (!mapping) {
        mapping = LookupName("");
    }
    if (mapping && (len <= AJ_MAX_NAME_SIZE)) {
        memcpy(&mapping->guid, guid, sizeof(AJ_GUID));
        memcpy(&mapping->uniqueName, uniqueName, len + 1);
        mapping->serviceName = serviceName;
        return AJ_OK;
    } else {
        AJ_ErrPrintf(("AJ_GUID_AddNameMapping(): AJ_ERR_RESOURCES\n"));
        return AJ_ERR_RESOURCES;
    }
}

void AJ_GUID_DeleteNameMapping(const char* uniqueName)
{
    NameToGUID* mapping;

    AJ_InfoPrintf(("AJ_GUID_AddNameMapping(uniqueName=\"%s\")\n", uniqueName));

    mapping = LookupName(uniqueName);
    if (mapping) {
        memset(mapping, 0, sizeof(NameToGUID));
    }
}

const AJ_GUID* AJ_GUID_Find(const char* name)
{
    NameToGUID* mapping = LookupName(name);
    AJ_InfoPrintf(("AJ_GUID_Find(name=\"%s\")\n", name));

    return mapping ? &mapping->guid : NULL;
}


void AJ_GUID_ClearNameMap(void)
{
    AJ_InfoPrintf(("AJ_GUID_ClearNameMap()\n"));
    memset(nameMap, 0, sizeof(nameMap));
}

AJ_Status AJ_SetGroupKey(const char* uniqueName, const uint8_t* key)
{
    NameToGUID* mapping;

    AJ_InfoPrintf(("AJ_SetGroupKey(uniqueName=\"%s\", key=0x%p)\n", uniqueName, key));

    mapping = LookupName(uniqueName);
    if (mapping) {
        memcpy(mapping->groupKey, key, 16);
        return AJ_OK;
    } else {
        AJ_WarnPrintf(("AJ_SetGroupKey(): AJ_ERR_NO_MATCH\n"));
        return AJ_ERR_NO_MATCH;
    }
}

AJ_Status AJ_SetSessionKey(const char* uniqueName, const uint8_t* key, uint8_t role)
{
    NameToGUID* mapping;

    AJ_InfoPrintf(("AJ_SetGroupKey(uniqueName=\"%s\", key=0x%p)\n", uniqueName, key));

    mapping = LookupName(uniqueName);
    if (mapping) {
        mapping->keyRole = role;
        memcpy(mapping->sessionKey, key, 16);
        return AJ_OK;
    } else {
        AJ_WarnPrintf(("AJ_SetSessionKey(): AJ_ERR_NO_MATCH\n"));
        return AJ_ERR_NO_MATCH;
    }
}

AJ_Status AJ_GetSessionKey(const char* name, uint8_t* key, uint8_t* role)
{
    NameToGUID* mapping;

    AJ_InfoPrintf(("AJ_GetSessionKey(name=\"%s\", key=0x%p, role=0x%p)\n", name, key, role));

    mapping = LookupName(name);
    if (mapping) {
        *role = mapping->keyRole;
        memcpy(key, mapping->sessionKey, 16);
        return AJ_OK;
    } else {
        AJ_WarnPrintf(("AJ_GetSessionKey(): AJ_ERR_NO_MATCH\n"));
        return AJ_ERR_NO_MATCH;
    }
}

AJ_Status AJ_GetGroupKey(const char* name, uint8_t* key)
{
    AJ_InfoPrintf(("AJ_GetGroupKey(name=\"%s\", key=0x%p)\n", name, key));
    if (name) {
        NameToGUID* mapping = LookupName(name);
        if (!mapping) {
            AJ_WarnPrintf(("AJ_GetGroupKey(): AJ_ERR_NO_MATCH\n"));
            return AJ_ERR_NO_MATCH;
        }
        memcpy(key, mapping->groupKey, 16);
    } else {
        /*
         * Check if the group key needs to be initialized
         */
        memset(key, 0, 16);
        if (memcmp(localGroupKey, key, 16) == 0) {
            AJ_RandBytes(localGroupKey, 16);
        }
        memcpy(key, localGroupKey, 16);
    }
    return AJ_OK;
}
