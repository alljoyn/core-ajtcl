/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2014 AllSeen Alliance. All rights reserved.
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
static AuthRecord* g_policy = NULL;
static AJ_ClaimState g_claimstate = AJ_CLAIM_UNKNOWN;
static uint8_t g_notify = FALSE;

static AJ_Status IdRecordCopy(IdRecord* dst, const IdRecord* src)
{
    dst->level = src->level;
    dst->typ = src->typ;
    if (AJ_ID_TYPE_ANY != dst->typ) {
        dst->guid = (AJ_GUID*) AJ_Malloc(sizeof (AJ_GUID));
        if (!dst->guid) {
            return AJ_ERR_RESOURCES;
        }
        memcpy(dst->guid, src->guid, sizeof (AJ_GUID));
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

    dst->idsnum = src->idsnum;
    dst->ids = (IdRecord*) AJ_Malloc(dst->idsnum * sizeof (IdRecord));
    if (!dst->ids) {
        return AJ_ERR_RESOURCES;
    }
    for (len = 0; (len < dst->idsnum) && (AJ_OK == status); len++) {
        status = IdRecordCopy(&dst->ids[len], &src->ids[len]);
    }
    if (AJ_OK != status) {
        return status;
    }
    dst->rulesnum = src->rulesnum;
    dst->rules = (RuleRecord*) AJ_Malloc(dst->rulesnum * sizeof (RuleRecord));
    if (!dst->rules) {
        return AJ_ERR_RESOURCES;
    }
    for (len = 0; (len < dst->rulesnum) && (AJ_OK == status); len++) {
        status = RuleRecordCopy(&dst->rules[len], &src->rules[len]);
    }

    return status;
}

static void IdRecordFree(IdRecord* record)
{
    if (AJ_ID_TYPE_ANY != record->typ) {
        if (record->guid) {
            AJ_Free(record->guid);
            record->guid = NULL;
        }
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

    for (i = 0; i < record->idsnum; i++) {
        IdRecordFree(&record->ids[i]);
    }
    if (record->ids) {
        AJ_Free(record->ids);
        record->ids = NULL;
    }
    for (i = 0; i < record->rulesnum; i++) {
        RuleRecordFree(&record->rules[i]);
    }
    if (record->rules) {
        AJ_Free(record->rules);
        record->rules = NULL;
    }
}

void AJ_AuthRecordFree(AuthRecord* record)
{
    AJ_InfoPrintf(("AJ_AuthRecordFree(record=%p)\n", record));
    TermRecordFree(&record->term);
    if (record) {
        AJ_Free(record);
        record = NULL;
    }
}

AJ_Status AJ_AuthRecordSet(const AuthRecord* record)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_AuthRecordSet(record=%p)\n", record));

    /*
     * Copy the record into the global policy
     */
    if (g_policy) {
        AJ_AuthRecordFree(g_policy);
    }
    g_policy = (AuthRecord*) AJ_Malloc(sizeof (AuthRecord));
    if (!g_policy) {
        return AJ_ERR_RESOURCES;
    }
    memset(g_policy, 0, sizeof (AuthRecord));
    g_policy->version = record->version;
    g_policy->serial = record->serial;
    status = TermRecordCopy(&g_policy->term, &record->term);

    return status;
}

static AJ_Status IdRecordFind(AJ_SecurityLevel level, uint8_t type, const AJ_GUID* guid)
{
    size_t i;
    IdRecord* id;

    if (!g_policy) {
        return AJ_ERR_SECURITY;
    }

    for (i = 0; i < g_policy->term.idsnum; i++) {
        id = &g_policy->term.ids[i];
        if (level == id->level) {
            switch (id->typ) {
            case AJ_ID_TYPE_ANY:
                return AJ_OK;

            case AJ_ID_TYPE_PEER:
            case AJ_ID_TYPE_GUILD:
                if ((type == id->typ) && (0 == memcmp(guid, id->guid, sizeof (AJ_GUID)))) {
                    return AJ_OK;
                }
                break;
            }
        }
    }

    return AJ_ERR_SECURITY;
}

AJ_Status AJ_AuthRecordApply(AJ_SecurityLevel level, uint8_t type, const AJ_GUID* guid, const char* peer)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_AuthRecordApply(level=%zu, type=%x, guid=%p, peer=%s)\n", level, type, guid, peer));

    status = IdRecordFind(level, type, guid);
    if (AJ_OK == status) {
        AJ_InfoPrintf(("AJ_AuthRecordApply(level=%zu, type=%x, guid=%p, peer=%s): Id found\n", level, type, guid, peer));
        strcpy(g_authtable.peer, peer);
        g_authtable.term = &g_policy->term;
    }

    return status;
}

static AJ_Status MemberRecordCheck(const MemberRecord* record, const char* mbr)
{
    if (0 == strcmp("*", record->mbr)) {
        return AJ_OK;
    }
    if (0 != strcmp(mbr, record->mbr)) {
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

    for (i = 0; i < record->rulesnum; i++) {
        status = RuleRecordCheck(&record->rules[i], obj, ifn, mbr);
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

    if (0 == strcmp("org.alljoyn.Bus.Peer.Authentication", msg->iface)) {
        return AJ_OK;
    }

    if (!g_authtable.term) {
        return AJ_ERR_SECURITY;
    }
    if (0 != strcmp(sender, g_authtable.peer)) {
        return AJ_ERR_SECURITY;
    }

    status = TermRecordCheck(g_authtable.term, msg->objPath, msg->iface, msg->member);
    AJ_InfoPrintf(("AJ_AuthRecordCheck(msg=%p, obj=%s, ifn=%s, mbr=%s): %s\n", msg, msg->objPath, msg->iface, msg->member, AJ_StatusText(status)));

    return status;
}

//SIG = (yyv)
static AJ_Status IdRecordUnmarshal(IdRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    uint8_t* buf;
    size_t len;
    char* tmp;
    uint8_t level;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalArgs(msg, "yy", &level, &record->typ);
    if (AJ_OK != status) {
        return status;
    }
    record->level = level;
    switch (record->typ) {
    case AJ_ID_TYPE_ANY:
        status = AJ_UnmarshalArgs(msg, "v", "ay", &buf, &len);
        break;

    case AJ_ID_TYPE_PEER:
    case AJ_ID_TYPE_GUILD:
        status = AJ_UnmarshalArgs(msg, "v", "ay", &buf, &len);
        if (AJ_OK == status) {
            if (sizeof (AJ_GUID) == len) {
                record->guid = (AJ_GUID*) buf;
            } else {
                status = AJ_ERR_INVALID;
            }
        }
        break;

    default:
        status = AJ_ERR_INVALID;
        break;
    }
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);

    return status;
}

//SIG = a(yyv)
static AJ_Status IdRecordsUnmarshal(TermRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    IdRecord tmp;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (AJ_OK == status) {
        status = IdRecordUnmarshal(&tmp, msg);
        if (AJ_OK != status) {
            break;
        }
        record->idsnum++;
        record->ids = AJ_Realloc(record->ids, sizeof (IdRecord) * record->idsnum);
        if (!record->ids) {
            return AJ_ERR_RESOURCES;
        }
        memcpy(&record->ids[record->idsnum - 1], &tmp, sizeof (IdRecord));
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

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
static AJ_Status RuleRecordsUnmarshal(TermRecord* record, AJ_Message* msg)
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
        record->rulesnum++;
        record->rules = AJ_Realloc(record->rules, sizeof (RuleRecord) * record->rulesnum);
        if (!record->rules) {
            return AJ_ERR_RESOURCES;
        }
        memcpy(&record->rules[record->rulesnum - 1], &tmp, sizeof (RuleRecord));
    }
    if (AJ_ERR_NO_MORE != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);

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

    record->ids = NULL;
    record->idsnum = 0;
    record->rules = NULL;
    record->rulesnum = 0;

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
            status = IdRecordsUnmarshal(record, msg);
            break;

        case 2:
            status = AJ_UnmarshalVariant(msg, (const char**) &variant);
            if (AJ_OK != status) {
                return status;
            }
            if (0 != strncmp(variant, "aa(yv)", 6)) {
                return AJ_ERR_INVALID;
            }
            status = RuleRecordsUnmarshal(record, msg);
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
AJ_Status AJ_AuthRecordUnmarshal(AuthRecord* record, AJ_Message* msg)
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

/*
 * PermissionMgmt Interface
 */
AJ_Status AJ_SecurityClaimMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;
    AJ_GUID guid;
    uint8_t* g;
    size_t glen;
    AJ_KeyInfo keyinfopub;
    AJ_KeyInfo keyinfoprv;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p)\n", msg, reply));

    if (!peerGuid) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_KeyInfoUnmarshal(&keyinfopub, msg, NULL);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    AJ_DumpBytes("KEYINFO", (uint8_t*) &keyinfopub, sizeof (AJ_KeyInfo));

    status = AJ_UnmarshalArgs(msg, "ay", &g, &glen);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    if (sizeof (AJ_GUID) != glen) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    memcpy(guid.val, g, sizeof (AJ_GUID));

    // This is my new GUID.. yay for me!
    status = AJ_SetLocalGUID(&guid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    AJ_DumpBytes("MY GUID", guid.val, sizeof (AJ_GUID));
    // Store my trust anchor
    status = AJ_KeyInfoSet(&keyinfopub, AJ_CRED_TYPE_ECDSA_CA_PUB, peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = AJ_KeyInfoGetLocal(&keyinfopub, AJ_CRED_TYPE_ECDSA_PUB);
    if (AJ_OK != status) {
        status = AJ_KeyInfoGenerate(&keyinfopub, &keyinfoprv, KEY_USE_SIG);
        if (AJ_OK != status) {
            return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
        }
        status = AJ_KeyInfoSetLocal(&keyinfopub, AJ_CRED_TYPE_ECDSA_PUB);
        if (AJ_OK != status) {
            return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
        }
        status = AJ_KeyInfoSetLocal(&keyinfoprv, AJ_CRED_TYPE_ECDSA_PRV);
        if (AJ_OK != status) {
            return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
        }
    }
    AJ_DumpBytes("KEYINFO", (uint8_t*) &keyinfopub, sizeof (AJ_KeyInfo));

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = AJ_KeyInfoMarshal(&keyinfopub, reply, NULL);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    g_notify = TRUE;

    return status;
}

AJ_Status AJ_SecurityInstallPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AuthRecord record;
    AJ_PeerCred cred;

    AJ_InfoPrintf(("AJ_SecurityInstallPolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    AJ_DumpBytes("MSG", msg->bus->sock.rx.readPtr, msg->hdr->bodyLen);

    /*
     * Store the policy as a marshalled message
     */
    cred.head.type = AJ_CRED_TYPE_POLICY;
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

    g_notify = TRUE;

    return status;
}

AJ_Status AJ_SecurityInstallEncryptedPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    return AJ_ERR_INVALID;
}

AJ_Status AJ_SecurityRemovePolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_PeerHead head;

    /*
     * Remove the in memory entry
     */
    if (g_policy) {
        AJ_AuthRecordFree(g_policy);
    }

    /*
     * Remove the persistent entry
     */
    head.type = AJ_CRED_TYPE_POLICY;
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

    g_notify = TRUE;

    return status;
}

AJ_Status AJ_SecurityGetPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_PeerHead head;
    AJ_PeerBody body;

    head.type = AJ_CRED_TYPE_POLICY;
    head.id.size = 0;
    head.id.data = NULL;

    status = AJ_GetCredential(&head, &body);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    /*
     * Need to marshal the raw body.data.data
     */
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        AJ_PeerBodyFree(&body);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    // TODO: need a raw (non partial) message delivery
    AJ_PeerBodyFree(&body);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);

    return status;
}

AJ_Status AJ_SecurityInstallIdentityMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    DER_Element der;
    AJ_PeerCred cred;
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

    cred.head.type = AJ_CRED_TYPE_X509_DER_IDN;
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
    AJ_PeerHead head;
    const AJ_GUID* issuer = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_SecurityRemoveIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    head.type = AJ_CRED_TYPE_X509_DER_IDN;
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
    AJ_PeerHead head;
    AJ_PeerBody body;
    const AJ_GUID* issuer = AJ_GUID_Find(msg->sender);
    uint8_t fmt = CERT_FMT_X509_DER;

    AJ_InfoPrintf(("AJ_SecurityGetIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    if (!issuer) {
        goto ExitFail;
    }

    head.type = AJ_CRED_TYPE_X509_DER_IDN;
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
    AJ_PeerCred cred;
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
        cred.head.type = AJ_CRED_TYPE_X509_DER_MBR;
        cred.body.expiration = 0xFFFFFFFF;
        cred.body.association.size = 0;
        cred.body.association.data = NULL;
        cred.body.data.size = der.size;
        cred.body.data.data = der.data;

        status = AJ_X509DecodeCertificateDER(&certificate, &der);
        if (AJ_OK != status) {
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
        AJ_PeerHeadFree(&cred.head);
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
    AJ_PeerCred cred;
    AuthRecord record;
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
    cred.head.type = AJ_CRED_TYPE_AUTHDATA;
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
    AJ_PeerHeadFree(&cred.head);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    status = AJ_AuthRecordUnmarshal(&record, msg);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    /*
     * Set the in memory policy
     */
    status = AJ_AuthRecordSet(&record);
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
    AJ_PeerHead head;
    uint8_t* serial;
    size_t seriallen;
    uint8_t* issuer;
    size_t issuerlen;

    AJ_InfoPrintf(("AJ_SecurityRemoveMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    status = AJ_UnmarshalArgs(msg, "ayay", &serial, &seriallen, &issuer, &issuerlen);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    head.type = AJ_CRED_TYPE_X509_DER_MBR;
    head.id.size = issuerlen + seriallen;
    head.id.data = AJ_Malloc(head.id.size);
    if (!head.id.data) {
        goto ExitFail;
    }
    memcpy(head.id.data, issuer, issuerlen);
    memcpy(head.id.data + issuerlen, serial, seriallen);

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

AJ_Status AJ_SecurityNotifyConfig(AJ_BusAttachment* bus)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_KeyInfo pub;
    uint32_t serial = 0;
    AJ_Arg container;

    if (!g_notify) {
        return AJ_OK;
    }
    g_notify = FALSE;

    AJ_InfoPrintf(("AJ_SecurityNotifyConfig(bus=%p)\n", bus));

    status = AJ_MarshalSignal(bus, &msg, AJ_SIGNAL_SECURITY_NOTIFY_CONFIG, NULL, 0, ALLJOYN_FLAG_SESSIONLESS, 0);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_KeyInfoGetLocal(&pub, AJ_CRED_TYPE_ECDSA_SIG_PUB);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_KeyInfoMarshal(&pub, &msg, NULL);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(&msg, "yu", (uint8_t) g_claimstate, serial);
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

AJ_Status AJ_SecurityInit()
{
    AJ_Status status;
    AJ_PeerHead head;
    AJ_KeyInfo pub;
    AJ_KeyInfo prv;

    AJ_InfoPrintf(("AJ_SecurityInit()\n"));

    /*
     * Check if I have any stored CAs
     */
    head.type = AJ_CRED_TYPE_ECDSA_CA_PUB;
    head.id.size = 0;
    head.id.data = NULL;
    status = AJ_GetCredential(&head, NULL);
    if (AJ_OK == status) {
        g_claimstate = AJ_CLAIM_CLAIMED;
        AJ_InfoPrintf(("AJ_SecurityInit(): In claimed state\n"));
    }

    /*
     * Check I have a key pair
     */
    status = AJ_KeyInfoGetLocal(&pub, AJ_CRED_TYPE_ECDSA_SIG_PUB);
    if (AJ_OK != status) {
        // Generate my communication signing key
        status = AJ_KeyInfoGenerate(&pub, &prv, KEY_USE_SIG);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&pub, AJ_CRED_TYPE_ECDSA_SIG_PUB);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&prv, AJ_CRED_TYPE_ECDSA_SIG_PRV);
        AJ_ASSERT(AJ_OK == status);
    }

    g_notify = TRUE;

    return status;
}

void AJ_SecurityClose()
{
    if (g_policy) {
        AJ_AuthRecordFree(g_policy);
    }
    g_policy = NULL;
}

AJ_Status AJ_SecuritySetClaimable(uint8_t claimable)
{
    if (claimable) {
        g_claimstate = AJ_CLAIM_CLAIMABLE;
    } else {
        g_claimstate = AJ_CLAIM_UNCLAIMABLE;
    }
    g_notify = TRUE;

    return AJ_OK;
}

AJ_ClaimState AJ_SecurityGetClaimState()
{
    return g_claimstate;
}
