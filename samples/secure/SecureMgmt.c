/*
 * securemgmt.c
 */

/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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

#define AJ_MODULE SECUREMGMT

#ifndef NO_SECURITY
#define SECURE_INTERFACE
#endif

#include <aj_target.h>
#include <alljoyn.h>
#include <aj_auth_listener.h>
#include <aj_cert.h>
#include <aj_creds.h>
#include <aj_crypto.h>
#include <aj_keyauthentication.h>
#include <aj_keyexchange.h>
#include <aj_peer.h>
#include <aj_security.h>
#include <aj_x509.h>
#include "aj_config.h"

uint8_t dbgSECUREMGMT = 1;
static const uint16_t ServicePort = 24;

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

#ifndef NGNS
#else
blah
#endif

#define CONNECT_TIMEOUT    (1000 * 200)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (1000 * 10)
#define PING_TIMEOUT       (1000 * 10)

static const uint8_t IDENTITY_CERTIFICATE_TEMPLATE[] = {
    0x30, 0x82, 0x01, 0x5d, 0x30, 0x82, 0x01, 0x02, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SERIAL NUM (8)
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x2b, 0x31, 0x29,
    0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //ISSUER GUID (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x1e, 0x17, 0x0d, 0x31, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x30, 0x2b, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SUBJECT GUID (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //PUBLIC KEY (64)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG R (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG S (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t MEMBERSHIP_CERTIFICATE_TEMPLATE[] = {
    0x30, 0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2d, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SERIAL NUM
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x2b, 0x31, 0x29,
    0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //ISSUER GUID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x1e, 0x17, 0x0d, 0x31, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x30, 0x56, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SUBJECT GUILD
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SUBJECT GUID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //PUBLIC KEY
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG R
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG S
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const char* levels[] = { "AJ_SESSION_NONE", "AJ_SESSION_ENCRYPTED", "AJ_SESSION_AUTHENTICATED", "AJ_SESSION_AUTHORISED" };
static void IdRecordDump(const IdRecord* record)
{
    char guid[2 * sizeof (AJ_GUID) + 1];

    AJ_ASSERT(record);
    AJ_ASSERT(record->level < 4);
    AJ_Printf("Level: %s ", levels[record->level]);
    switch (record->typ) {
    case AJ_ID_TYPE_ANY:
        AJ_Printf("Any\n");
        break;

    case AJ_ID_TYPE_PEER:
        AJ_GUID_ToString(record->guid, guid, sizeof (guid));
        AJ_Printf("Peer %s\n", guid);
        break;

    case AJ_ID_TYPE_GUILD:
        AJ_GUID_ToString(record->guid, guid, sizeof (guid));
        AJ_Printf("Guild %s\n", guid);
        break;
    }
}

static void IdRecordsDump(const TermRecord* record)
{
    size_t i;

    AJ_ASSERT(record);
    for (i = 0; i < record->idsnum; i++) {
        IdRecordDump(&record->ids[i]);
    }
}

static const char* types[] = { "METHOD", "SIGNAL", "PROPERTY" };
static void MemberRecordDump(const MemberRecord* record)
{
    AJ_ASSERT(record);
    AJ_ASSERT(record->typ < 3);
    AJ_Printf("Mbr: %s (%s) %d %s\n", record->mbr, types[record->typ], record->action, record->mutual ? "mutual" : "");
}

static void MemberRecordsDump(const RuleRecord* record)
{
    size_t i;

    AJ_ASSERT(record);
    for (i = 0; i < record->mbrsnum; i++) {
        MemberRecordDump(&record->mbrs[i]);
    }
}

static void RuleRecordDump(const RuleRecord* record)
{
    AJ_ASSERT(record);
    AJ_Printf("Obj: %s ", record->obj);
    AJ_Printf("Ifn: %s\n", record->ifn);
    MemberRecordsDump(record);
}

static void RuleRecordsDump(const TermRecord* record)
{
    size_t i;

    AJ_ASSERT(record);
    for (i = 0; i < record->rulesnum; i++) {
        RuleRecordDump(&record->rules[i]);
    }
}

static void TermRecordDump(const TermRecord* record)
{
    AJ_ASSERT(record);
    IdRecordsDump(record);
    RuleRecordsDump(record);
}

void AJ_AuthRecordDump(const AuthRecord* record)
{
    AJ_InfoPrintf(("AJ_AuthRecordDump(record=%p)\n", record));
    AJ_ASSERT(record);
    AJ_Printf("Version %d Serial %d\n", record->version, record->serial);
    TermRecordDump(&record->term);
}

AJ_Status AJ_X509Sign(X509Certificate* certificate, const AJ_KeyInfo* key)
{
    return AJ_ECDSASign(certificate->tbs.data, certificate->tbs.size, &key->key.privatekey, &certificate->signature);
}

AJ_Status AJ_X509EncodeIdentityCertificateSig(X509Certificate* certificate, DER_Element* der)
{
    AJ_Status status = AJ_OK;
    size_t rpos = 286;
    size_t spos = 321;

    AJ_BigvalEncode(&certificate->signature.r, der->data + rpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->signature.s, der->data + spos, KEY_ECC_SZ);

    return status;
}

AJ_Status AJ_X509EncodeMembershipCertificateSig(X509Certificate* certificate, DER_Element* der)
{
    AJ_Status status = AJ_OK;
    size_t rpos = 329;
    size_t spos = 364;

    AJ_BigvalEncode(&certificate->signature.r, der->data + rpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->signature.s, der->data + spos, KEY_ECC_SZ);

    return status;
}

AJ_Status AJ_X509EncodeIdentityCertificateDER(X509Certificate* certificate, DER_Element* der)
{
    AJ_Status status = AJ_OK;
    size_t serpos = 15;
    size_t isspos = 48;
    size_t subpos = 125;
    size_t xpos = 184;
    size_t ypos = 216;
    char guid[1 + 2 * sizeof (AJ_GUID)];

    der->size = sizeof (IDENTITY_CERTIFICATE_TEMPLATE);
    der->data = AJ_Malloc(der->size);
    AJ_ASSERT(der->data);

    memcpy(der->data, IDENTITY_CERTIFICATE_TEMPLATE, der->size);
    certificate->serial.data = der->data + serpos;
    certificate->serial.size = 8;
    status = AJ_GUID_ToString(&certificate->issuer, guid, sizeof (guid));
    AJ_ASSERT(AJ_OK == status);
    memcpy(der->data + isspos, &guid, 2 * sizeof (AJ_GUID));
    status = AJ_GUID_ToString(&certificate->subject, guid, sizeof (guid));
    AJ_ASSERT(AJ_OK == status);
    memcpy(der->data + subpos, &guid, 2 * sizeof (AJ_GUID));
    AJ_BigvalEncode(&certificate->publickey.x, der->data + xpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->publickey.y, der->data + ypos, KEY_ECC_SZ);

    certificate->tbs.data = der->data + 4;
    certificate->tbs.size = 262;

    return status;
}

AJ_Status AJ_X509EncodeMembershipCertificateDER(X509Certificate* certificate, DER_Element* der)
{
    AJ_Status status = AJ_OK;
    size_t serpos = 15;
    size_t isspos = 48;
    size_t guildpos = 125;
    size_t subpos = 168;
    size_t xpos = 227;
    size_t ypos = 259;
    char guid[1 + 2 * sizeof (AJ_GUID)];

    der->size = sizeof (MEMBERSHIP_CERTIFICATE_TEMPLATE);
    der->data = AJ_Malloc(der->size);
    AJ_ASSERT(der->data);

    memcpy(der->data, MEMBERSHIP_CERTIFICATE_TEMPLATE, der->size);
    certificate->serial.data = der->data + serpos;
    certificate->serial.size = 8;
    status = AJ_GUID_ToString(&certificate->issuer, guid, sizeof (guid));
    AJ_ASSERT(AJ_OK == status);
    memcpy(der->data + isspos, &guid, 2 * sizeof (AJ_GUID));
    status = AJ_GUID_ToString(&certificate->guild, guid, sizeof (guid));
    AJ_ASSERT(AJ_OK == status);
    memcpy(der->data + guildpos, &guid, 2 * sizeof (AJ_GUID));
    status = AJ_GUID_ToString(&certificate->subject, guid, sizeof (guid));
    AJ_ASSERT(AJ_OK == status);
    memcpy(der->data + subpos, &guid, 2 * sizeof (AJ_GUID));
    AJ_BigvalEncode(&certificate->publickey.x, der->data + xpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->publickey.y, der->data + ypos, KEY_ECC_SZ);

    certificate->tbs.data = der->data + 4;
    certificate->tbs.size = 305;

    return status;
}

#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential*cred)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_Printf("AuthListenerCallback authmechanism %d command %d\n", authmechanism, command);

    return status;
}
#endif

#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
void AuthCallback(const void* context, AJ_Status status)
{
    *((AJ_Status*)context) = status;
    AJ_Printf("Authentication Callback: status = %d\n", status);
}
#endif

void Callback(const void* context, AJ_Status status)
{
    AJ_Printf("Callback: status = %d\n", status);
}

static AJ_GUID claimee;
static AJ_Status AJ_SecurityClaim(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_KeyInfo keyinfopub;
    AJ_KeyInfo keyinfoprv;

    AJ_InfoPrintf(("AJ_SecurityClaim(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_KeyInfoGetLocal(&keyinfopub, AJ_CRED_TYPE_ECDSA_PUB);
    if (AJ_OK != status) {
        status = AJ_KeyInfoGenerate(&keyinfopub, &keyinfoprv, KEY_USE_SIG);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&keyinfopub, AJ_CRED_TYPE_ECDSA_PUB);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&keyinfoprv, AJ_CRED_TYPE_ECDSA_PRV);
        AJ_ASSERT(AJ_OK == status);
    }
    AJ_DumpBytes("KEYINFO", (uint8_t*) &keyinfopub, sizeof (AJ_KeyInfo));

    // Give it a random guid - we need to save this
    AJ_RandBytes(claimee.val, sizeof (AJ_GUID));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_CLAIM, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoMarshal(&keyinfopub, &msg, NULL);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(&msg, "ay", claimee.val, sizeof (claimee));
    AJ_ASSERT(AJ_OK == status);

    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityClaimReply(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    AJ_KeyInfo keyinfopub;

    AJ_InfoPrintf(("AJ_SecurityClaimReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_SecurityClaimReply(msg=%p): error=%s.\n", msg, msg->error));
        return AJ_OK;
    }

    status = AJ_KeyInfoUnmarshal(&keyinfopub, msg, NULL);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("KEYINFO", (uint8_t*) &keyinfopub, sizeof (AJ_KeyInfo));

    // Store this key
    status = AJ_KeyInfoSet(&keyinfopub, AJ_CRED_TYPE_ECDSA_PUB, &claimee);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = (yyv)
static AJ_Status IdRecordMarshal(const IdRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    uint8_t level = record->level;
    uint8_t typ = record->typ;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_STRUCT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "yy", level, typ);
    AJ_ASSERT(AJ_OK == status);
    switch (record->typ) {
    case AJ_ID_TYPE_ANY:
        status = AJ_MarshalArgs(msg, "v", "ay", record->guid, 0);
        AJ_ASSERT(AJ_OK == status);
        break;

    case AJ_ID_TYPE_PEER:
        AJ_ASSERT(record->guid);
        status = AJ_MarshalArgs(msg, "v", "ay", record->guid, sizeof (AJ_GUID));
        AJ_ASSERT(AJ_OK == status);
        break;

    case AJ_ID_TYPE_GUILD:
        AJ_ASSERT(record->guid);
        status = AJ_MarshalArgs(msg, "v", "ay", record->guid, sizeof (AJ_GUID));
        AJ_ASSERT(AJ_OK == status);
        break;

    default:
        AJ_ASSERT(0);
        return AJ_ERR_INVALID;
    }

    status = AJ_MarshalCloseContainer(msg, &container);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = a(yyv)
static AJ_Status IdRecordsMarshal(TermRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    size_t i;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    AJ_ASSERT(AJ_OK == status);
    for (i = 0; i < record->idsnum; i++) {
        status = IdRecordMarshal(&record->ids[i], msg);
        AJ_ASSERT(AJ_OK == status);
    }
    status = AJ_MarshalCloseContainer(msg, &container);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = a(yv)
static AJ_Status MemberRecordMarshal(const MemberRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "(yv)", 1, "s", record->mbr);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "(yv)", 2, "y", record->typ);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "(yv)", 3, "y", record->action);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "(yv)", 4, "b", record->mutual);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = aa(yv)
static AJ_Status MemberRecordsMarshal(RuleRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    size_t i;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    AJ_ASSERT(AJ_OK == status);
    for (i = 0; i < record->mbrsnum; i++) {
        status = MemberRecordMarshal(&record->mbrs[i], msg);
        AJ_ASSERT(AJ_OK == status);
    }
    status = AJ_MarshalCloseContainer(msg, &container);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = a(yv)
static AJ_Status RuleRecordMarshal(RuleRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "(yv)", 1, "s", record->obj);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "(yv)", 2, "s", record->ifn);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "y", 3);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalVariant(msg, "aa(yv)");
    AJ_ASSERT(AJ_OK == status);
    status = MemberRecordsMarshal(record, msg);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container2);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container1);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = aa(yv)
static AJ_Status RuleRecordsMarshal(TermRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    size_t i;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    AJ_ASSERT(AJ_OK == status);
    for (i = 0; i < record->rulesnum; i++) {
        status = RuleRecordMarshal(&record->rules[i], msg);
        AJ_ASSERT(AJ_OK == status);
    }
    status = AJ_MarshalCloseContainer(msg, &container1);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = a(yv)
static AJ_Status TermRecordMarshal(TermRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "y", 1);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalVariant(msg, "a(yyv)");
    AJ_ASSERT(AJ_OK == status);
    status = IdRecordsMarshal(record, msg);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container2);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "y", 2);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalVariant(msg, "aa(yv)");
    AJ_ASSERT(AJ_OK == status);
    status = RuleRecordsMarshal(record, msg);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container2);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container1);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

//SIG = (yv)
static AJ_Status AJ_AuthRecordMarshal(AuthRecord* record, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    AJ_ASSERT(record);
    AJ_ASSERT(msg);
    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_STRUCT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "y", record->version);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalVariant(msg, "(ua(yv))");
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(msg, "u", record->serial);
    AJ_ASSERT(AJ_OK == status);
    status = TermRecordMarshal(&record->term, msg);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container2);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(msg, &container1);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_GUID guild = { { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 } };
//static IdRecord idrecord = { AJ_SESSION_AUTHENTICATED, AJ_ID_TYPE_ANY, NULL };
static IdRecord idrecord = { AJ_SESSION_AUTHENTICATED, AJ_ID_TYPE_GUILD, &guild };
static char* testobj = "/org/alljoyn/alljoyn_test";
static char* testifn = "org.alljoyn.alljoyn_test";
static MemberRecord memberrecord1 = { "my_ping", 0, AJ_ACTION_PROVIDE, 1 };
static MemberRecord memberrecord2 = { "my_ping", 0, AJ_ACTION_CONSUME, 1 };
static RuleRecord rulerecord;
//static TermRecord termrecord;
static AuthRecord policy;
static AuthRecord authdata;

void CreatePolicy()
{
    rulerecord.obj = testobj;
    rulerecord.ifn = testifn;
    rulerecord.mbrsnum = 1;
    rulerecord.mbrs = &memberrecord1;
    policy.version = 0;
    policy.serial = 1;
    policy.term.idsnum = 1;
    policy.term.ids = &idrecord;
    policy.term.rulesnum = 1;
    policy.term.rules = &rulerecord;
}

void CreateAuthData()
{
    rulerecord.obj = testobj;
    rulerecord.ifn = testifn;
    rulerecord.mbrsnum = 1;
    rulerecord.mbrs = &memberrecord2;
    authdata.version = 0;
    authdata.serial = 1;
    authdata.term.idsnum = 1;
    authdata.term.ids = &idrecord;
    authdata.term.rulesnum = 1;
    authdata.term.rules = &rulerecord;
}

static AJ_Status AJ_SecurityInstallPolicy(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityInstallPolicy(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    CreatePolicy();
    AJ_AuthRecordDump(&policy);
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_INSTALL_POLICY, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_AuthRecordMarshal(&policy, &msg);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityInstallPolicyReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityInstallPolicyReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityInstallPolicyReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status AJ_SecurityRemovePolicy(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityRemovePolicy(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_REMOVE_POLICY, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityRemovePolicyReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityRemovePolicyReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityRemovePolicyReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status AJ_SecurityGetPolicy(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityGetPolicy(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_GET_POLICY, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityGetPolicyReply(AJ_Message* msg)
{
    AJ_Status status;
    AuthRecord record;

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityGetPolicyReply(msg=%p): error=%s.\n", msg, msg->error));
        return AJ_ERR_SECURITY;
    } else {
        AJ_InfoPrintf(("AJ_SecurityGetPolicyReply(msg=%p): OK\n", msg));
    }

    status = AJ_AuthRecordUnmarshal(&record, msg);
    AJ_ASSERT(AJ_OK == status);
    AJ_AuthRecordDump(&record);

    return status;
}

static AJ_Status AJ_SecurityInstallIdentity(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;
    X509Certificate certificate;
    AJ_KeyInfo prv;
    AJ_KeyInfo pub;
    AJ_GUID issuer;
    const AJ_GUID* subject = AJ_GUID_Find(peer);
    DER_Element der;
    uint8_t fmt = CERT_FMT_X509_DER;

    AJ_InfoPrintf(("AJ_SecurityInstallIdentity(bus=%p, peer=%s, session=%d)\n", bus, peer, session));

    AJ_ASSERT(subject);
    status = AJ_GetLocalGUID(&issuer);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGetLocal(&prv, AJ_CRED_TYPE_ECDSA_PRV);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGet(&pub, AJ_CRED_TYPE_ECDSA_PUB, subject);
    AJ_ASSERT(AJ_OK == status);

    memcpy(&certificate.publickey, &pub.key.publickey, sizeof (ecc_publickey));
    memcpy(&certificate.issuer, &issuer, sizeof (AJ_GUID));
    memcpy(&certificate.subject, subject, sizeof (AJ_GUID));
    status = AJ_X509EncodeIdentityCertificateDER(&certificate, &der);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_X509Sign(&certificate, &prv);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_X509EncodeIdentityCertificateSig(&certificate, &der);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("DER", der.data, der.size);

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_INSTALL_IDENTITY, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(&msg, "(yay)", fmt, der.data, der.size);
    AJ_ASSERT(AJ_OK == status);

    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    AJ_Free(der.data);

    return status;
}

static AJ_Status AJ_SecurityInstallIdentityReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityInstallIdentityReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityInstallIdentityReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status AJ_SecurityRemoveIdentity(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityRemoveIdentity(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_REMOVE_IDENTITY, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityRemoveIdentityReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityRemoveIdentityReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityRemoveIdentityReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status AJ_SecurityGetIdentity(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityGetIdentity(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_GET_IDENTITY, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityGetIdentityReply(AJ_Message* msg)
{
    AJ_Status status;
    uint8_t fmt;
    DER_Element der;

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityGetIdentityReply(msg=%p): error=%s.\n", msg, msg->error));
        return AJ_ERR_SECURITY;
    } else {
        AJ_InfoPrintf(("AJ_SecurityGetIdentityReply(msg=%p): OK\n", msg));
    }

    status = AJ_UnmarshalArgs(msg, "(yay)", &fmt, &der.data, &der.size);
    AJ_ASSERT(AJ_OK == status);
    AJ_ASSERT(CERT_FMT_X509_DER == fmt);
    AJ_DumpBytes("DER", der.data, der.size);

    return status;
}

static AJ_Status AJ_SecurityInstallMembership(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;
    X509Certificate certificate;
    AJ_KeyInfo prv;
    AJ_KeyInfo pub;
    AJ_GUID issuer;
    const AJ_GUID* subject = AJ_GUID_Find(peer);
    DER_Element der;
    uint8_t fmt = CERT_FMT_X509_DER;
    AJ_GUID guild;
    AJ_Arg container;

    AJ_InfoPrintf(("AJ_SecurityInstallMembership(bus=%p, peer=%s, session=%d)\n", bus, peer, session));

    memset(&guild, 1, sizeof (AJ_GUID));
    AJ_ASSERT(subject);
    status = AJ_GetLocalGUID(&issuer);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGetLocal(&prv, AJ_CRED_TYPE_ECDSA_PRV);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGet(&pub, AJ_CRED_TYPE_ECDSA_PUB, subject);
    AJ_ASSERT(AJ_OK == status);

    memcpy(&certificate.publickey, &pub.key.publickey, sizeof (ecc_publickey));
    memcpy(&certificate.issuer, &issuer, sizeof (AJ_GUID));
    memcpy(&certificate.guild, &guild, sizeof (AJ_GUID));
    memcpy(&certificate.subject, subject, sizeof (AJ_GUID));
    status = AJ_X509EncodeMembershipCertificateDER(&certificate, &der);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_X509Sign(&certificate, &prv);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_X509EncodeMembershipCertificateSig(&certificate, &der);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("DER", der.data, der.size);

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_INSTALL_MEMBERSHIP, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalContainer(&msg, &container, AJ_ARG_ARRAY);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(&msg, "(yay)", fmt, der.data, der.size);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalCloseContainer(&msg, &container);
    AJ_ASSERT(AJ_OK == status);

    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    AJ_Free(der.data);

    return status;
}

static AJ_Status AJ_SecurityInstallMembershipReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityInstallMembershipReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityInstallMembershipReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status AJ_SecurityInstallMembershipAuthData(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;
    AJ_GUID issuer;
    uint8_t serial[8];

    AJ_InfoPrintf(("AJ_SecurityInstallMembershipAuthData(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_GetLocalGUID(&issuer);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("ISS", (uint8_t*) &issuer, sizeof (AJ_GUID));
    //Smarter security manager needs to track serial numbers
    memset(serial, 0, sizeof (serial));
    AJ_DumpBytes("SER", (uint8_t*) &serial, sizeof (serial));
    CreateAuthData();
    AJ_AuthRecordDump(&authdata);
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_INSTALL_AUTHDATA, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(&msg, "ayay", serial, sizeof (serial), &issuer, sizeof (AJ_GUID));
    AJ_ASSERT(AJ_OK == status);
    status = AJ_AuthRecordMarshal(&authdata, &msg);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityInstallMembershipAuthDataReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityInstallMembershipAuthDataReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityInstallMembershipAuthDataReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status AJ_SecurityRemoveMembership(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_GUID issuer;
    uint8_t serial[8];

    AJ_InfoPrintf(("AJ_SecurityRemoveMembership(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_GetLocalGUID(&issuer);
    AJ_ASSERT(AJ_OK == status);
    //Smarter security manager needs to track serial numbers
    memset(serial, 0, sizeof (serial));
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_REMOVE_MEMBERSHIP, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_MarshalArgs(&msg, "ayay", serial, sizeof (serial), &issuer, sizeof (AJ_GUID));
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return AJ_OK;
}

static AJ_Status AJ_SecurityRemoveMembershipReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityRemoveMembershipReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityRemoveMembershipReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status CallInterface(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName, const char* interfaceName, uint32_t type)
{
    AJ_InfoPrintf(("CallInterface %s on service %s\n", interfaceName, serviceName));

    if (0 == strcmp(interfaceName, "claim")) {
        AJ_SecurityClaim(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "installpolicy")) {
        AJ_SecurityInstallPolicy(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "removepolicy")) {
        AJ_SecurityRemovePolicy(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "getpolicy")) {
        AJ_SecurityGetPolicy(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "installidentity")) {
        AJ_SecurityInstallIdentity(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "removeidentity")) {
        AJ_SecurityRemoveIdentity(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "getidentity")) {
        AJ_SecurityGetIdentity(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "installmembership")) {
        AJ_SecurityInstallMembership(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "installmembershipauthdata")) {
        AJ_SecurityInstallMembershipAuthData(bus, serviceName, sessionId);
    } else if (0 == strcmp(interfaceName, "removemembership")) {
        AJ_SecurityRemoveMembership(bus, serviceName, sessionId);
    }

    return AJ_OK;
}

#ifdef MAIN_ALLOWS_ARGS
int AJ_Main(int ac, char** av)
#else
int AJ_Main()
#endif
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;
    AJ_Status authStatus = AJ_ERR_NULL;
    char* serviceName = NULL;
    char* interfaceName = NULL;
    uint32_t suites[3];
    size_t numsuites = 0;
    uint8_t clearkeys = FALSE;
    uint8_t running = TRUE;
    uint32_t type = AUTH_SUITE_ECDHE_NULL;

#ifdef MAIN_ALLOWS_ARGS
#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
    uint8_t getAuth;
    ac--;
    av++;
    /*
     * Enable authentication mechanism by command line
     */
    while (ac) {
        getAuth = 0;
        if (0 == strncmp(*av, "-ek", 3)) {
            clearkeys = TRUE;
            getAuth = 1;
            ac--;
            av++;
        } else if (0 == strncmp(*av, "-e", 2)) {
            getAuth = 1;
            ac--;
            av++;
        }
        if (getAuth) {
            if (!ac) {
                AJ_Printf("-e(k) requires an auth mechanism.\n");
                return 1;
            }
            if (0 == strncmp(*av, "ECDHE_ECDSA", 11)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
            } else if (0 == strncmp(*av, "ECDHE_PSK", 9)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
            } else if (0 == strncmp(*av, "ECDHE_NULL", 10)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
            }
            ac--;
            av++;
        } else if (0 == strncmp(*av, "-s", 2)) {
            ac--;
            av++;
            if (!ac) {
                AJ_Printf("-s requires a service name.\n");
                return 1;
            }
            serviceName = *av;
            ac--;
            av++;
        } else if (0 == strncmp(*av, "-id", 3)) {
            ac--;
            av++;
            if (!ac) {
                AJ_Printf("-id requires a type.\n");
                return 1;
            }
            if (0 == strncmp(*av, "ECDHE_ECDSA", 11)) {
                type = AUTH_SUITE_ECDHE_ECDSA;
            } else if (0 == strncmp(*av, "ECDHE_PSK", 9)) {
                type = AUTH_SUITE_ECDHE_PSK;
            } else if (0 == strncmp(*av, "ECDHE_NULL", 10)) {
                type = AUTH_SUITE_ECDHE_NULL;
            }
            ac--;
            av++;
        } else if (0 == strncmp(*av, "-i", 2)) {
            ac--;
            av++;
            if (!ac) {
                AJ_Printf("-i requires an interface name.\n");
                return 1;
            }
            interfaceName = *av;
            ac--;
            av++;
        }
    }

    if (!serviceName) {
        AJ_Printf("Service required\n");
        return 1;
    }
    if (!interfaceName) {
        AJ_Printf("Interface required\n");
        return 1;
    }
#endif
#endif

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    while (running) {
        AJ_Message msg;

        if (!connected) {
#ifndef NGNS
            status = AJ_StartClient(&bus, NULL, CONNECT_TIMEOUT, FALSE, serviceName, ServicePort, &sessionId, NULL);
#else
            status = AJ_StartClientByInterface(&bus, NULL, CONNECT_TIMEOUT, FALSE, testInterfaceNames, &sessionId, serviceName, NULL);
#endif
            if (status == AJ_OK) {
                AJ_Printf("StartClient returned %d, sessionId=%u, serviceName=%s\n", status, sessionId, serviceName);
                AJ_Printf("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus));
                connected = TRUE;
#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
                AJ_BusEnableSecurity(&bus, suites, ArraySize(suites));
                AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
                if (clearkeys) {
                    status = AJ_ClearCredentials();
                    AJ_ASSERT(AJ_OK == status);
                }
                status = AJ_BusAuthenticatePeer(&bus, serviceName, AuthCallback, &authStatus);
                if (status != AJ_OK) {
                    AJ_Printf("AJ_BusAuthenticatePeer returned %d\n", status);
                }
#else
                authStatus = AJ_OK;
#endif
            } else {
                AJ_Printf("StartClient returned %d\n", status);
                break;
            }
        }

        AJ_Printf("Auth status %d and AllJoyn status %d\n", authStatus, status);

        if (status == AJ_ERR_RESOURCES) {
            AJ_InfoPrintf(("Peer is busy, disconnecting and retrying auth...\n"));
            AJ_Disconnect(&bus);
            connected = FALSE;
            continue;
        }

        if (authStatus != AJ_ERR_NULL) {
            if (authStatus != AJ_OK) {
                AJ_Disconnect(&bus);
                break;
            }
            authStatus = AJ_ERR_NULL;
            AJ_BusSetLinkTimeout(&bus, sessionId, 10 * 1000);
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                continue;
            }
        } else {
            switch (msg.msgId) {

            case AJ_REPLY_ID(AJ_METHOD_SET_LINK_TIMEOUT):
                {
                    uint32_t disposition;
                    uint32_t timeout;
                    status = AJ_UnmarshalArgs(&msg, "uu", &disposition, &timeout);
                    if (disposition == AJ_SETLINKTIMEOUT_SUCCESS) {
                        AJ_Printf("Link timeout set to %d\n", timeout);
                    } else {
                        AJ_Printf("SetLinkTimeout failed %d\n", disposition);
                    }
                    CallInterface(&bus, sessionId, serviceName, interfaceName, type);
                }
                break;

            case AJ_REPLY_ID(AJ_METHOD_BUS_PING):
                {
                    uint32_t disposition;
                    status = AJ_UnmarshalArgs(&msg, "u", &disposition);
                    if (disposition == AJ_PING_SUCCESS) {
                        AJ_Printf("Bus Ping reply received\n");
                    } else {
                        AJ_Printf("Bus Ping failed, disconnecting: %d\n", disposition);
                        status = AJ_ERR_LINK_DEAD;
                    }
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /*
                 * Force a disconnect
                 */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_Printf("Session lost. ID = %u, reason = %u\n", id, reason);
                }
                status = AJ_ERR_SESSION_LOST;
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_CLAIM):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_CLAIM)\n"));
                status = AJ_SecurityClaimReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_POLICY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_POLICY)\n"));
                status = AJ_SecurityInstallPolicyReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_POLICY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_POLICY)\n"));
                status = AJ_SecurityRemovePolicyReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_POLICY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_POLICY)\n"));
                status = AJ_SecurityGetPolicyReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_IDENTITY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_INSTALL_IDENTITY)\n"));
                status = AJ_SecurityInstallIdentityReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_IDENTITY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_REMOVE_IDENTITY)\n"));
                status = AJ_SecurityRemoveIdentityReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_IDENTITY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_GET_IDENTITY)\n"));
                status = AJ_SecurityGetIdentityReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_MEMBERSHIP):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_MEMBERSHIP)\n"));
                status = AJ_SecurityInstallMembershipReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_AUTHDATA):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_AUTHDATA)\n"));
                status = AJ_SecurityInstallMembershipAuthDataReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_MEMBERSHIP):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_MEMBERSHIP)\n"));
                status = AJ_SecurityRemoveMembershipReply(&msg);
                AJ_Disconnect(&bus);
                connected = FALSE;
                return AJ_OK;

            case AJ_SIGNAL_SECURITY_NOTIFY_CONFIG:
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_SIGNAL_SECURITY_NOTIFY_CONFIG\n"));
                break;

            default:
                /*
                 * Pass to the built-in handlers
                 */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }
        /*
         * Messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_SESSION_LOST) || (status == AJ_ERR_READ) || (status == AJ_ERR_LINK_DEAD)) {
            AJ_Printf("AllJoyn disconnect\n");
            AJ_Printf("Disconnected from Daemon:%s\n", AJ_GetUniqueName(&bus));
            AJ_Disconnect(&bus);
            return status;
        }
    }
    AJ_Printf("secure client EXIT %d\n", status);

    return status;
}

#ifdef AJ_MAIN
#ifdef MAIN_ALLOWS_ARGS
int main(int ac, char** av)
{
    return AJ_Main(ac, av);
}
#else
int main()
{
    return AJ_Main();
}
#endif
#endif
