/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2014-2015, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE SECURITY

#include "aj_target.h"
#include "aj_security.h"
#include "aj_std.h"
#include "aj_debug.h"
#include "aj_peer.h"
#include "aj_crypto_ecc.h"
#include "aj_guid.h"
#include "aj_cert.h"
#include "aj_config.h"
#include "aj_creds.h"
#include "aj_crypto.h"
#include "aj_x509.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgSECURITY = 0;
#endif

typedef struct _AuthTable {
    char peer[AJ_MAX_NAME_SIZE + 1];
    TermRecord* term;
} AuthTable;
static AuthTable g_authtable;
static AJ_AuthRecord* g_policy = NULL;
static AJ_Manifest* g_manifest = NULL;
static AJ_ClaimState claimstate = AJ_CLAIM_UNKNOWN;
static uint8_t notify = FALSE;

static AJ_Status IdRecordCopy(AJ_Identity* dst, const AJ_Identity* src)
{
    dst->level = src->level;
    dst->type = src->type;
    dst->data = NULL;
    dst->size = src->size;

    if (dst->size) {
        dst->data = AJ_Malloc(dst->size);
        if (!dst->data) {
            return AJ_ERR_RESOURCES;
        }
        memcpy(dst->data, src->data, dst->size);
    }

    return AJ_OK;
}

static AJ_Status MemberRecordCopy(MemberRecord* dst, const MemberRecord* src)
{
    size_t len;

    len = strlen(src->mbr);
    dst->mbr = (char*) AJ_Malloc(len + 1);
    if (!dst->mbr) {
        return AJ_ERR_RESOURCES;
    }
    memcpy(dst->mbr, src->mbr, len + 1); // Copies NULL termination
    dst->typ = src->typ;
    dst->action = src->action;
    dst->mutual = src->mutual;

    return AJ_OK;
}

static AJ_Status RuleRecordCopy(RuleRecord* dst, const RuleRecord* src)
{
    AJ_Status status = AJ_OK;
    size_t len;

    len = strlen(src->obj);
    dst->obj = (char*) AJ_Malloc(len + 1);
    if (!dst->obj) {
        return AJ_ERR_RESOURCES;
    }
    memcpy(dst->obj, src->obj, len + 1); // Copies NULL termination
    len = strlen(src->ifn);
    dst->ifn = (char*) AJ_Malloc(len + 1);
    if (!dst->ifn) {
        return AJ_ERR_RESOURCES;
    }
    memcpy(dst->ifn, src->ifn, len + 1); // Copies NULL termination
    dst->mbrsnum = src->mbrsnum;
    dst->mbrs = (MemberRecord*) AJ_Malloc(dst->mbrsnum * sizeof (MemberRecord));
    if (!dst->mbrs) {
        return AJ_ERR_RESOURCES;
    }
    for (len = 0; (len < dst->mbrsnum) && (AJ_OK == status); len++) {
        status = MemberRecordCopy(&dst->mbrs[len], &src->mbrs[len]);
    }

    return status;
}

static AJ_Status TermRecordCopy(TermRecord* dst, const TermRecord* src)
{
    AJ_Status status = AJ_OK;
    size_t len;

    dst->ids.num = src->ids.num;
    dst->ids.id = (AJ_Identity*) AJ_Malloc(dst->ids.num * sizeof (AJ_Identity));
    if (!dst->ids.id) {
        return AJ_ERR_RESOURCES;
    }
    for (len = 0; (len < dst->ids.num) && (AJ_OK == status); len++) {
        status = IdRecordCopy(&dst->ids.id[len], &src->ids.id[len]);
    }
    if (AJ_OK != status) {
        return status;
    }
    dst->rules.num = src->rules.num;
    dst->rules.rule = (RuleRecord*) AJ_Malloc(dst->rules.num * sizeof (RuleRecord));
    if (!dst->rules.rule) {
        return AJ_ERR_RESOURCES;
    }
    for (len = 0; (len < dst->rules.num) && (AJ_OK == status); len++) {
        status = RuleRecordCopy(&dst->rules.rule[len], &src->rules.rule[len]);
    }

    return status;
}

static void IdRecordFree(AJ_Identity* record)
{
    if (record->data) {
        AJ_Free(record->data);
        record->data = NULL;
        record->size = 0;
    }
}

static void RuleRecordFree(RuleRecord* record)
{
    size_t i;

    if (record->obj) {
        AJ_Free(record->obj);
        record->obj = NULL;
    }
    if (record->ifn) {
        AJ_Free(record->ifn);
        record->ifn = NULL;
    }
    for (i = 0; i < record->mbrsnum; i++) {
        if (record->mbrs[i].mbr) {
            AJ_Free(record->mbrs[i].mbr);
            record->mbrs[i].mbr = NULL;
        }
    }
}

static void TermRecordFree(TermRecord* record)
{
    size_t i;

    for (i = 0; i < record->ids.num; i++) {
        IdRecordFree(&record->ids.id[i]);
    }
    if (record->ids.id) {
        AJ_Free(record->ids.id);
        record->ids.id = NULL;
    }
    for (i = 0; i < record->rules.num; i++) {
        RuleRecordFree(&record->rules.rule[i]);
    }
    if (record->rules.rule) {
        AJ_Free(record->rules.rule);
        record->rules.rule = NULL;
    }
}

void AJ_AuthRecordFree(AJ_AuthRecord* record)
{
    AJ_InfoPrintf(("AJ_AuthRecordFree(record=%p)\n", record));
    TermRecordFree(&record->term);
    if (record) {
        AJ_Free(record);
        record = NULL;
    }
}

void AJ_ManifestFree(AJ_Manifest* manifest)
{
    size_t i;

    AJ_InfoPrintf(("AJ_ManifestFree(manifest=%p)\n", manifest));

    for (i = 0; i < manifest->rules.num; i++) {
        RuleRecordFree(&manifest->rules.rule[i]);
    }
    if (manifest->rules.rule) {
        AJ_Free(manifest->rules.rule);
        manifest->rules.rule = NULL;
    }
}

AJ_Status AJ_AuthRecordSet(const AJ_AuthRecord* record)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_AuthRecordSet(record=%p)\n", record));

    /*
     * Copy the record into the global policy
     */
    if (g_policy) {
        AJ_AuthRecordFree(g_policy);
    }
    g_policy = (AJ_AuthRecord*) AJ_Malloc(sizeof (AJ_AuthRecord));
    if (!g_policy) {
        return AJ_ERR_RESOURCES;
    }
    memset(g_policy, 0, sizeof (AJ_AuthRecord));
    g_policy->version = record->version;
    g_policy->serial = record->serial;
    status = TermRecordCopy(&g_policy->term, &record->term);

    return status;
}

AJ_Status AJ_AuthRecordLoad(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_Message msg;
    AJ_CredHead head;
    AJ_CredBody body;
    AJ_AuthRecord record;
    uint8_t* readPtr;

    AJ_InfoPrintf(("AJ_AuthRecordLoad(bus=%p)\n", bus));

    head.type = AJ_POLICY_LOCAL | AJ_CRED_TYPE_POLICY;
    head.id.size = 0;
    head.id.data = NULL;
    status = AJ_GetCredential(&head, &body);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_AuthRecordLoad(bus=%p): No stored policy\n", bus));
        return AJ_OK;
    }

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_INSTALL_POLICY, "org.tmp", 1, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    if (AJ_OK != status) {
        return status;
    }
    msg.hdr->bodyLen = body.data.size;
    msg.bodyBytes = body.data.size;

    /*
     * Point the rx buffer at the marshalled body
     */
    readPtr = bus->sock.rx.readPtr;
    bus->sock.rx.readPtr = body.data.data;

    status = AJ_AuthRecordUnmarshal(&record, &msg);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_AuthRecordSet(&record);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_CloseMsg(&msg);
    if (AJ_OK != status) {
        goto Exit;
    }

    AJ_InfoPrintf(("AJ_AuthRecordLoad(bus=%p): Policy loaded\n", bus));

Exit:
    /*
     * Put the rx buffer back where it was
     */
    AJ_CredBodyFree(&body);
    bus->sock.rx.readPtr = readPtr;

    return status;
}

static AJ_Status IdRecordFind(AJ_Identity* record)
{
    size_t i;
    AJ_Identity* id;

    if (!g_policy) {
        return AJ_ERR_SECURITY;
    }

    for (i = 0; i < g_policy->term.ids.num; i++) {
        id = &g_policy->term.ids.id[i];
        if (id->level != record->level) {
            continue;
        }
        if (id->type != record->type) {
            continue;
        }
        if (0 == memcmp(id->data, record->data, record->size)) {
            return AJ_OK;
        }
    }

    return AJ_ERR_SECURITY;
}

AJ_Status AJ_AuthRecordApply(AJ_Identity* record, const char* peer)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_AuthRecordApply(record=%p, peer=%s): Level %x Type %x\n", record, peer, record->level, record->type));
    AJ_DumpBytes("DATA", record->data, record->size);

    status = IdRecordFind(record);
    if (AJ_OK == status) {
        strcpy(g_authtable.peer, peer);
        g_authtable.term = &g_policy->term;
    }
    AJ_InfoPrintf(("AJ_AuthRecordApply(record=%p, peer=%s): Id found %s\n", record, peer, AJ_StatusText(status)));

    return status;
}

static AJ_Status MemberRecordCheck(const MemberRecord* record, const char* mbr)
{
    if (0 == strncmp(record->mbr, "*", 1)) {
        return AJ_OK;
    }
    if (0 != strcmp(record->mbr, mbr)) {
        return AJ_ERR_SECURITY;
    }

    return AJ_OK;
}

static AJ_Status RuleRecordCheck(const RuleRecord* record, const char* obj, const char* ifn, const char* mbr)
{
    AJ_Status status;
    size_t i;

    if (0 != strcmp(obj, record->obj)) {
        return AJ_ERR_SECURITY;
    }
    if (0 != strcmp(ifn, record->ifn)) {
        return AJ_ERR_SECURITY;
    }
    for (i = 0; i < record->mbrsnum; i++) {
        status = MemberRecordCheck(&record->mbrs[i], mbr);
        if (AJ_OK == status) {
            return status;
        }
    }

    return AJ_ERR_SECURITY;
}

static AJ_Status TermRecordCheck(const TermRecord* record, const char* obj, const char* ifn, const char* mbr)
{
    AJ_Status status;
    size_t i;

    for (i = 0; i < record->rules.num; i++) {
        status = RuleRecordCheck(&record->rules.rule[i], obj, ifn, mbr);
        if (AJ_OK == status) {
            return status;
        }
    }

    return AJ_ERR_SECURITY;
}

AJ_Status AJ_AuthRecordCheck(const AJ_Message* msg)
{
    AJ_Status status;
    const char* sender = msg->sender;

    AJ_InfoPrintf(("AJ_AuthRecordCheck(msg=%p)\n", msg));

    if (0 == strncmp(msg->iface, "org.alljoyn.Bus.Peer.Authentication", 35)) {
        return AJ_OK;
    }

    if (!g_authtable.term) {
        AJ_InfoPrintf(("AJ_AuthRecordCheck(msg=%p): no policy for sender\n", msg));
        return AJ_ERR_SECURITY;
    }
    if (0 != strncmp(sender, g_authtable.peer, AJ_MAX_NAME_SIZE)) {
        AJ_InfoPrintf(("AJ_AuthRecordCheck(msg=%p): sender not in table\n", msg));
        return AJ_ERR_SECURITY;
    }

    status = TermRecordCheck(g_authtable.term, msg->objPath, msg->iface, msg->member);
    AJ_InfoPrintf(("AJ_AuthRecordCheck(msg=%p, obj=%s, ifn=%s, mbr=%s): %s\n", msg, msg->objPath, msg->iface, msg->member, AJ_StatusText(status)));

    return status;
}

//SIG = (yyv)
static AJ_Status IdRecordMarshal(const AJ_Identity* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    uint8_t level = record->level;

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "yy", level, record->type);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "v", "ay", record->data, record->size);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

//SIG = (yyv)
static AJ_Status IdRecordUnmarshal(AJ_Identity* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    uint8_t level;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "yy", &level, &record->type);
    if (AJ_OK != status) {
        return status;
    }
    record->level = level;
    status = AJ_UnmarshalArgs(msg, "v", "ay", &record->data, &record->size);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}

//SIG = a(yyv)
static AJ_Status IdRecordsMarshal(const IdRecords* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    size_t i;

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    for (i = 0; i < record->num; i++) {
        status = IdRecordMarshal(&record->id[i], msg);
        if (AJ_OK != status) {
            return status;
        }
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

//SIG = a(yyv)
static AJ_Status IdRecordsUnmarshal(IdRecords* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Identity tmp;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = IdRecordUnmarshal(&tmp, msg);
        if (AJ_OK != status) {
            break;
        }
        record->num++;
        record->id = AJ_Realloc(record->id, sizeof (AJ_Identity) * record->num);
        if (!record->id) {
            return AJ_ERR_RESOURCES;
        }
        memcpy(&record->id[record->num - 1], &tmp, sizeof (AJ_Identity));
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = a(yv)
static AJ_Status MemberRecordMarshal(const MemberRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "(yv)", 1, "s", record->mbr);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "(yv)", 2, "y", record->typ);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "(yv)", 3, "y", record->action);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "(yv)", 4, "b", record->mutual);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

//SIG = a(yv)
static AJ_Status MemberRecordUnmarshal(MemberRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t field;

    //Default record to DENIED
    record->action = AJ_ACTION_DENIED;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_UnmarshalArgs(msg, "y", &field);
        if (AJ_OK != status) {
            return status;
        }
        switch (field) {
        case 1:
            status = AJ_UnmarshalArgs(msg, "v", "s", &record->mbr);
            break;

        case 2:
            status = AJ_UnmarshalArgs(msg, "v", "y", &record->typ);
            break;

        case 3:
            status = AJ_UnmarshalArgs(msg, "v", "y", &record->action);
            break;

        case 4:
            status = AJ_UnmarshalArgs(msg, "v", "b", &record->mutual);
            break;

        default:
            status = AJ_ERR_INVALID;
            break;
        }
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            return status;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = aa(yv)
static AJ_Status MemberRecordsMarshal(const RuleRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    size_t i;

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    for (i = 0; i < record->mbrsnum; i++) {
        status = MemberRecordMarshal(&record->mbrs[i], msg);
        if (AJ_OK != status) {
            return status;
        }
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

//SIG = aa(yv)
static AJ_Status MemberRecordsUnmarshal(RuleRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    MemberRecord tmp;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = MemberRecordUnmarshal(&tmp, msg);
        if (AJ_OK != status) {
            break;
        }
        record->mbrsnum++;
        record->mbrs = AJ_Realloc(record->mbrs, sizeof (MemberRecord) * record->mbrsnum);
        if (!record->mbrs) {
            return AJ_ERR_RESOURCES;
        }
        memcpy(&record->mbrs[record->mbrsnum - 1], &tmp, sizeof (MemberRecord));
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = a(yv)
static AJ_Status RuleRecordMarshal(const RuleRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "(yv)", 1, "s", record->obj);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "(yv)", 2, "s", record->ifn);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "y", 3);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalVariant(msg, "aa(yv)");
    if (AJ_OK != status) {
        return status;
    }
    status = MemberRecordsMarshal(record, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = a(yv)
static AJ_Status RuleRecordUnmarshal(RuleRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t field;
    char* variant;

    record->mbrs = NULL;
    record->mbrsnum = 0;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_UnmarshalArgs(msg, "y", &field);
        if (AJ_OK != status) {
            return status;
        }
        switch (field) {
        case 1:
            status = AJ_UnmarshalArgs(msg, "v", "s", &record->obj);
            break;

        case 2:
            status = AJ_UnmarshalArgs(msg, "v", "s", &record->ifn);
            break;

        case 3:
            status = AJ_UnmarshalVariant(msg, (const char**) &variant);
            if (AJ_OK != status) {
                return status;
            }
            if (0 != strncmp(variant, "aa(yv)", 6)) {
                return AJ_ERR_INVALID;
            }
            status = MemberRecordsUnmarshal(record, msg);
            break;

        default:
            status = AJ_ERR_INVALID;
        }
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            return status;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = aa(yv)
static AJ_Status RuleRecordsMarshal(const RuleRecords* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    size_t i;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    for (i = 0; i < record->num; i++) {
        status = RuleRecordMarshal(&record->rule[i], msg);
        if (AJ_OK != status) {
            return status;
        }
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = aa(yv)
static AJ_Status RuleRecordsUnmarshal(RuleRecords* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    RuleRecord tmp;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = RuleRecordUnmarshal(&tmp, msg);
        if (AJ_OK != status) {
            break;
        }
        record->num++;
        record->rule = AJ_Realloc(record->rule, sizeof (RuleRecord) * record->num);
        if (!record->rule) {
            return AJ_ERR_RESOURCES;
        }
        memcpy(&record->rule[record->num - 1], &tmp, sizeof (RuleRecord));
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = a(yv)
static AJ_Status TermRecordMarshal(const TermRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "y", 1);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalVariant(msg, "a(yyv)");
    if (AJ_OK != status) {
        return status;
    }
    status = IdRecordsMarshal(&record->ids, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "y", 2);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalVariant(msg, "aa(yv)");
    if (AJ_OK != status) {
        return status;
    }
    status = RuleRecordsMarshal(&record->rules, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = a(yv)
static AJ_Status TermRecordUnmarshal(TermRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t field;
    char* variant;

    record->ids.id = NULL;
    record->ids.num = 0;
    record->rules.rule = NULL;
    record->rules.num = 0;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_UnmarshalArgs(msg, "y", &field);
        if (AJ_OK != status) {
            return status;
        }
        switch (field) {
        case 1:
            status = AJ_UnmarshalVariant(msg, (const char**) &variant);
            if (AJ_OK != status) {
                return status;
            }
            if (0 != strncmp(variant, "a(yyv)", 6)) {
                return AJ_ERR_INVALID;
            }
            status = IdRecordsUnmarshal(&record->ids, msg);
            break;

        case 2:
            status = AJ_UnmarshalVariant(msg, (const char**) &variant);
            if (AJ_OK != status) {
                return status;
            }
            if (0 != strncmp(variant, "aa(yv)", 6)) {
                return AJ_ERR_INVALID;
            }
            status = RuleRecordsUnmarshal(&record->rules, msg);
            break;

        default:
            status = AJ_ERR_INVALID;
        }
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            return status;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = (yv)
AJ_Status AJ_AuthRecordMarshal(const AJ_AuthRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "y", record->version);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalVariant(msg, "(ua(yv))");
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "u", record->serial);
    if (AJ_OK != status) {
        return status;
    }
    status = TermRecordMarshal(&record->term, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = (yv)
AJ_Status AJ_AuthRecordUnmarshal(AJ_AuthRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    char* variant;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "y", &record->version);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != record->version) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(ua(yv))", 8)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "u", &record->serial);
    if (AJ_OK != status) {
        return status;
    }
    status = TermRecordUnmarshal(&record->term, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = (yv)
AJ_Status AJ_ManifestMarshal(const AJ_Manifest* manifest, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "y", 1);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalVariant(msg, "aa(yv)");
    if (AJ_OK != status) {
        return status;
    }
    status = RuleRecordsMarshal(&manifest->rules, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = (yv)
AJ_Status AJ_ManifestUnmarshal(AJ_Manifest* manifest, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    uint8_t field;
    char* variant;

    manifest->rules.rule = NULL;
    manifest->rules.num = 0;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "y", &field);
    if (AJ_OK != status) {
        return status;
    }
    if (1 != field) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "aa(yv)", 6)) {
        return AJ_ERR_INVALID;
    }
    status = RuleRecordsUnmarshal(&manifest->rules, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

    return status;
}

AJ_Status AJ_SecurityInit(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_CredHead head;
    AJ_KeyInfo pub;
    AJ_KeyInfo prv;
    uint8_t bound = FALSE;

    AJ_InfoPrintf(("AJ_SecurityInit()\n"));

    /*
     * Check if I have any stored CAs
     */
    head.type = AJ_KEYINFO_ECDSA_CA_PUB | AJ_CRED_TYPE_KEYINFO;
    head.id.size = 0;
    head.id.data = NULL;
    status = AJ_GetCredential(&head, NULL);
    if (AJ_OK == status) {
        claimstate = AJ_CLAIM_CLAIMED;
        AJ_InfoPrintf(("AJ_SecurityInit(): In claimed state\n"));
    }

    /*
     * Check I have a key pair
     */
    status = AJ_KeyInfoGetLocal(&pub, AJ_KEYINFO_ECDSA_SIG_PUB);
    if (AJ_OK != status) {
        // Generate my communication signing key
        status = AJ_KeyInfoGenerate(&pub, &prv, KEY_USE_SIG);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_KeyInfoSetLocal(&pub, AJ_KEYINFO_ECDSA_SIG_PUB);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_KeyInfoSetLocal(&prv, AJ_KEYINFO_ECDSA_SIG_PRV);
        if (AJ_OK != status) {
            return status;
        }
    }

    /*
     * Bind to the security management port
     */
    AJ_InfoPrintf(("AJ_SecurityInit(): Bind Session Port %d\n", AJ_SECURE_MGMT_PORT));
    status = AJ_BusBindSessionPort(bus, AJ_SECURE_MGMT_PORT, NULL, 0);
    if (AJ_OK != status) {
        return status;
    }
    while (!bound && (AJ_OK == status)) {
        AJ_Message msg;
        status = AJ_UnmarshalMsg(bus, &msg, AJ_UNMARSHAL_TIMEOUT);
        if (AJ_OK != status) {
            break;
        }
        switch (msg.msgId) {
        case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
            if (msg.hdr->msgType == AJ_MSG_ERROR) {
                AJ_ErrPrintf(("AJ_SecurityInit(): AJ_METHOD_BIND_SESSION_PORT: %s\n", msg.error));
                status = AJ_ERR_FAILURE;
            } else {
                AJ_InfoPrintf(("AJ_SecurityInit(): AJ_METHOD_BIND_SESSION_PORT: OK\n"));
                notify = TRUE;
                bound = TRUE;
                status = AJ_OK;
            }
            break;

        }
        AJ_CloseMsg(&msg);
    }

    return status;
}

void AJ_SecurityClose()
{
    if (g_policy) {
        AJ_AuthRecordFree(g_policy);
    }
    g_policy = NULL;
}

void AJ_SecuritySetClaimable(uint8_t claimable)
{
    if (claimable) {
        claimstate = AJ_CLAIM_CLAIMABLE;
    } else {
        claimstate = AJ_CLAIM_UNCLAIMABLE;
    }
}

AJ_ClaimState AJ_SecurityGetClaimState()
{
    return claimstate;
}

/*
 * PermissionMgmt Interface
 */
AJ_Status AJ_SecurityClaimMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;
    AJ_GUID guid;
    uint8_t* g;
    size_t glen;
    AJ_KeyInfo pub;
    const AJ_GUID* issuer = AJ_GUID_Find(msg->sender);
    uint8_t fmt;
    DER_Element der;
    AJ_Cred cred;

    AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p)\n", msg, reply));

    if (AJ_CLAIM_CLAIMABLE != claimstate) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    if (!issuer) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    // Unmarshal my trust anchor public key
    status = AJ_KeyInfoUnmarshal(&pub, msg, NULL);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    AJ_DumpBytes("KEYINFO", (uint8_t*) &pub, sizeof (AJ_KeyInfo));

    status = AJ_UnmarshalArgs(msg, "ay", &g, &glen);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    if (sizeof (AJ_GUID) != glen) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    memcpy(guid.val, g, sizeof (AJ_GUID));

    // Claiming may involve issuing a new guid, still in discussion.
    //status = AJ_SetLocalGUID(&guid);
    //if (AJ_OK != status) {
    //    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    //}

    AJ_DumpBytes("MY GUID", guid.val, sizeof (AJ_GUID));
    // Store my trust anchor
    status = AJ_KeyInfoSet(&pub, AJ_KEYINFO_ECDSA_CA_PUB, issuer);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_UnmarshalArgs(msg, "(yay)", &fmt, &der.data, &der.size);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    if (CERT_FMT_X509_DER != fmt) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    AJ_DumpBytes("DER", der.data, der.size);

    cred.head.type = AJ_CERTIFICATE_IDN_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
    //Certificate issuer should be the same as the sender
    cred.head.id.size = sizeof (AJ_GUID);
    cred.head.id.data = (uint8_t*) issuer;
    cred.body.expiration = 0xFFFFFFFF;
    cred.body.association.size = 0;
    cred.body.association.data = NULL;
    cred.body.data.size = der.size;
    cred.body.data.data = der.data;

    status = AJ_StoreCredential(&cred);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    claimstate = AJ_CLAIM_CLAIMED;
    notify = TRUE;

    return status;
}

AJ_Status AJ_SecurityInstallPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_AuthRecord record;
    AJ_Cred cred;

    AJ_InfoPrintf(("AJ_SecurityInstallPolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    /*
     * Store the policy as a marshalled message
     */
    cred.head.type = AJ_POLICY_LOCAL | AJ_CRED_TYPE_POLICY;
    cred.head.id.size = 0;
    cred.head.id.data = NULL;
    cred.body.expiration = 0xFFFFFFFF;
    cred.body.association.size = 0;
    cred.body.association.data = NULL;
    cred.body.data.size = msg->hdr->bodyLen;
    cred.body.data.data = msg->bus->sock.rx.readPtr;
    status = AJ_StoreCredential(&cred);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_AuthRecordUnmarshal(&record, msg);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    /*
     * Set the in memory policy
     */
    status = AJ_AuthRecordSet(&record);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    notify = TRUE;

    return status;
}

AJ_Status AJ_SecurityInstallEncryptedPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityInstallEncryptedPolicyMethod(msg=%p, reply=%p)\n", msg, reply));
    return AJ_ERR_INVALID;
}

AJ_Status AJ_SecurityRemovePolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredHead head;

    AJ_InfoPrintf(("AJ_SecurityRemovePolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    /*
     * Remove the in memory entry
     */
    if (g_policy) {
        AJ_AuthRecordFree(g_policy);
    }

    /*
     * Remove the persistent entry
     */
    head.type = AJ_POLICY_LOCAL | AJ_CRED_TYPE_POLICY;
    head.id.size = 0;
    head.id.data = NULL;
    status = AJ_DeleteCredential(&head);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    return status;
}

AJ_Status AJ_SecurityGetPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredHead head;
    AJ_CredBody body;

    AJ_InfoPrintf(("AJ_SecurityGetPolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    head.type = AJ_POLICY_LOCAL | AJ_CRED_TYPE_POLICY;
    head.id.size = 0;
    head.id.data = NULL;

    status = AJ_GetCredential(&head, &body);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_CredBodyMarshal(&body, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:

    AJ_CredBodyFree(&body);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityInstallIdentityMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    DER_Element der;
    AJ_Cred cred;
    const AJ_GUID* issuer = AJ_GUID_Find(msg->sender);
    uint8_t fmt;

    AJ_InfoPrintf(("AJ_SecurityInstallIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    if (!issuer) {
        goto ExitFail;
    }

    status = AJ_UnmarshalArgs(msg, "(yay)", &fmt, &der.data, &der.size);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    if (CERT_FMT_X509_DER != fmt) {
        goto ExitFail;
    }
    AJ_DumpBytes("DER", der.data, der.size);

    cred.head.type = AJ_CERTIFICATE_IDN_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
    //Certificate issuer should be the same as the sender
    cred.head.id.size = sizeof (AJ_GUID);
    cred.head.id.data = (uint8_t*) issuer;
    cred.body.expiration = 0xFFFFFFFF;
    cred.body.association.size = 0;
    cred.body.association.data = NULL;
    cred.body.data.size = der.size;
    cred.body.data.data = der.data;

    status = AJ_StoreCredential(&cred);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityRemoveIdentityMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredHead head;
    const AJ_GUID* issuer = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_SecurityRemoveIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    head.type = AJ_CERTIFICATE_IDN_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
    head.id.size = sizeof (AJ_GUID);
    head.id.data = (uint8_t*) issuer;
    status = AJ_DeleteCredential(&head);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityGetIdentityMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredHead head;
    AJ_CredBody body;
    const AJ_GUID* issuer = AJ_GUID_Find(msg->sender);
    uint8_t fmt = CERT_FMT_X509_DER;

    AJ_InfoPrintf(("AJ_SecurityGetIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    if (!issuer) {
        goto ExitFail;
    }

    head.type = AJ_CERTIFICATE_IDN_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
    head.id.size = sizeof (AJ_GUID);
    head.id.data = (uint8_t*) issuer;
    status = AJ_GetCredential(&head, &body);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalArgs(reply, "(yay)", fmt, body.data.data, body.data.size);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityInstallMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    DER_Element der;
    AJ_Cred cred;
    const AJ_GUID* issuer = AJ_GUID_Find(msg->sender);
    uint8_t fmt;
    X509Certificate certificate;
    AJ_Arg container;

    AJ_InfoPrintf(("AJ_SecurityInstallMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    if (!issuer) {
        goto ExitFail;
    }

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalArgs(msg, "(yay)", &fmt, &der.data, &der.size);
        if (AJ_OK != status) {
            break;
        }
        if (CERT_FMT_X509_DER != fmt) {
            goto ExitFail;
        }
        AJ_DumpBytes("DER", der.data, der.size);

        //Keep reference to der before we decode it (it will be consumed)
        cred.head.type = AJ_CERTIFICATE_MBR_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
        cred.body.expiration = 0xFFFFFFFF;
        cred.body.association.size = 0;
        cred.body.association.data = NULL;
        cred.body.data.size = der.size;
        cred.body.data.data = der.data;

        status = AJ_X509DecodeCertificateDER(&certificate, &der);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_SecurityInstallMembershipMethod(msg=%p, reply=%p): Decode DER failed\n", msg, reply));
            goto ExitFail;
        }
        cred.head.id.size = sizeof (AJ_GUID) + certificate.serial.size;
        cred.head.id.data = AJ_Malloc(cred.head.id.size);
        if (!cred.head.id.data) {
            goto ExitFail;
        }
        memcpy(cred.head.id.data, (uint8_t*) &certificate.issuer, sizeof (AJ_GUID));
        memcpy(cred.head.id.data + sizeof (AJ_GUID), certificate.serial.data, certificate.serial.size);
        AJ_DumpBytes("ID", cred.head.id.data, cred.head.id.size);

        status = AJ_StoreCredential(&cred);
        AJ_CredHeadFree(&cred.head);
        if (AJ_OK != status) {
            goto ExitFail;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityInstallMembershipAuthDataMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Cred cred;
    uint8_t* serial;
    size_t seriallen;
    uint8_t* issuer;
    size_t issuerlen;

    AJ_InfoPrintf(("AJ_SecurityInstallMembershipAuthDataMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_UnmarshalArgs(msg, "ayay", &serial, &seriallen, &issuer, &issuerlen);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    /*
     * Store the policy as a marshalled message
     */
    cred.head.type = AJ_POLICY_MEMBERSHIP | AJ_CRED_TYPE_POLICY;
    cred.head.id.size = issuerlen + seriallen;
    cred.head.id.data = AJ_Malloc(cred.head.id.size);
    if (!cred.head.id.data) {
        goto ExitFail;
    }
    memcpy(cred.head.id.data, issuer, issuerlen);
    memcpy(cred.head.id.data + issuerlen, serial, seriallen);
    AJ_DumpBytes("ID", cred.head.id.data, cred.head.id.size);
    cred.body.expiration = 0xFFFFFFFF;
    cred.body.association.size = 0;
    cred.body.association.data = NULL;
    cred.body.data.size = msg->hdr->bodyLen;
    cred.body.data.data = msg->bus->sock.rx.readPtr;
    status = AJ_StoreCredential(&cred);
    AJ_CredHeadFree(&cred.head);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityRemoveMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredHead head;
    uint8_t* serial;
    size_t seriallen;
    uint8_t* issuer;
    size_t issuerlen;

    AJ_InfoPrintf(("AJ_SecurityRemoveMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_UnmarshalArgs(msg, "ayay", &serial, &seriallen, &issuer, &issuerlen);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    head.type = AJ_CERTIFICATE_MBR_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
    head.id.size = issuerlen + seriallen;
    head.id.data = AJ_Malloc(head.id.size);
    if (!head.id.data) {
        goto ExitFail;
    }
    memcpy(head.id.data, issuer, issuerlen);
    memcpy(head.id.data + issuerlen, serial, seriallen);

    status = AJ_DeleteCredential(&head);
    AJ_CredHeadFree(&head);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecuritySetManifest(AJ_Manifest* manifest)
{
    AJ_InfoPrintf(("AJ_SecuritySetManifest(manifest=%p)\n", manifest));

    g_manifest = manifest;

    return AJ_OK;
}

AJ_Status AJ_SecurityGetManifestMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_SecurityGetManifestMethod(msg=%p, reply=%p)\n", msg, reply));

    if (!g_manifest) {
        AJ_InfoPrintf(("AJ_SecurityGetManifestMethod(msg=%p, reply=%p): No manifest set by application\n", msg, reply));
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = AJ_ManifestMarshal(g_manifest, reply);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    return status;
}

AJ_Status AJ_SecurityResetMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_SecurityResetMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_ClearCredentials(0);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    notify = TRUE;
    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityGetPublicKeyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_KeyInfo pub;

    AJ_InfoPrintf(("AJ_SecurityGetPublicKeyMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_KeyInfoGetLocal(&pub, AJ_KEYINFO_ECDSA_SIG_PUB);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_KeyInfoMarshal(&pub, reply, NULL);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_SecurityNotifyConfig(AJ_BusAttachment* bus)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_KeyInfo pub;
    uint32_t serial = 0;
    AJ_Arg container;

    if (!notify) {
        return AJ_OK;
    }
    notify = FALSE;

    AJ_InfoPrintf(("AJ_SecurityNotifyConfig(bus=%p)\n", bus));

    status = AJ_MarshalSignal(bus, &msg, AJ_SIGNAL_SECURITY_NOTIFY_CONFIG, NULL, 0, ALLJOYN_FLAG_SESSIONLESS, 0);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_KeyInfoGetLocal(&pub, AJ_KEYINFO_ECDSA_SIG_PUB);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_KeyInfoMarshal(&pub, &msg, NULL);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(&msg, "yu", (uint8_t) claimstate, serial);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalContainer(&msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(&msg, &container);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_DeliverMsg(&msg);

    return status;
}
