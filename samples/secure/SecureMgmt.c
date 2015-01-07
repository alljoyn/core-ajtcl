/*
 * securemgmt.c
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
static const uint16_t ManagementPort = AJ_SECURE_MGMT_PORT;

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
    0x30, 0x82, 0x01, 0xbe,
    0x30, 0x82, 0x01, 0x63,
    0xa0, 0x03,
    0x02, 0x01, 0x02,
    0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                    //SERIAL NUM (8)
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x30, 0x2b,
    0x31, 0x29,
    0x30, 0x27,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //ISSUER GUID (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x17, 0x0d, 0x31, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x30, 0x2b,
    0x31, 0x29,
    0x30, 0x27,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SUBJECT GUID (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x59,
    0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //PUBLIC KEY (64)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x71,
    0x30, 0x6f,
    0x30, 0x0c,
    0x06, 0x03, 0x55, 0x1d, 0x13,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00,                                                      //BASIC CONSTRAINTS
    0x30, 0x13,
    0x06, 0x0a, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x01,
    0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01,                                                      //TYPE
    0x30, 0x0b,
    0x06, 0x03, 0x55, 0x1d, 0x11,
    0x04, 0x04, 0x70, 0x68, 0x69, 0x6c,
    0x30, 0x3d,
    0x06, 0x0a, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x02,
    0x04, 0x2f,
    0x30, 0x2d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x04, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //DIGEST
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x49, 0x00,
    0x30, 0x46,
    0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG R (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG S (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t MEMBERSHIP_CERTIFICATE_TEMPLATE[] = {
    0x30, 0x82, 0x01, 0xdc,
    0x30, 0x82, 0x01, 0x81,
    0xa0, 0x03,
    0x02, 0x01, 0x02,
    0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                    //SERIAL NUM (8)
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x30, 0x2b,
    0x31, 0x29,
    0x30, 0x27,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //ISSUER GUID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x17, 0x0d, 0x31, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    0x30, 0x56,
    0x31, 0x29,
    0x30, 0x27,
    0x06, 0x03, 0x55, 0x04, 0x0B,
    0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SUBJECT GUILD
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0x29,
    0x30, 0x27,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SUBJECT GUID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x59,
    0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //PUBLIC KEY
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x64,
    0x30, 0x62,
    0x30, 0x0c,
    0x06, 0x03, 0x55, 0x1d, 0x13,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00,                                                      //BASIC CONSTRAINTS
    0x30, 0x13,
    0x06, 0x0a, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x01,
    0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02,                                                      //TYPE
    0x30, 0x3d,
    0x06, 0x0a, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x7C, 0x01, 0x02,
    0x04, 0x2f,
    0x30, 0x2d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x04, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //DIGEST
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x49, 0x00,
    0x30, 0x46,
    0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG R
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //SIG S
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const char* levels[] = { "AJ_SESSION_NONE", "AJ_SESSION_ENCRYPTED", "AJ_SESSION_AUTHENTICATED", "AJ_SESSION_AUTHORISED" };
static void IdRecordDump(const AJ_Identity* record)
{
    AJ_ASSERT(record);
    AJ_ASSERT(record->level < ArraySize(levels));
    AJ_Printf("Level: %s ", levels[record->level]);
    if (AJ_ID_TYPE_ANY != record->type) {
        AJ_DumpBytes("ID", record->data, record->size);
    }
}

static void IdRecordsDump(const IdRecords* record)
{
    size_t i;

    AJ_ASSERT(record);
    for (i = 0; i < record->num; i++) {
        IdRecordDump(&record->id[i]);
    }
}

static const char* types[] = { "METHOD", "SIGNAL", "PROPERTY" };
static void MemberRecordDump(const MemberRecord* record)
{
    AJ_ASSERT(record);
    AJ_ASSERT(record->typ < ArraySize(types));
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

static void RuleRecordsDump(const RuleRecords* record)
{
    size_t i;

    AJ_ASSERT(record);
    for (i = 0; i < record->num; i++) {
        RuleRecordDump(&record->rule[i]);
    }
}

static void TermRecordDump(const TermRecord* record)
{
    AJ_ASSERT(record);
    IdRecordsDump(&record->ids);
    RuleRecordsDump(&record->rules);
}

static void AJ_AuthRecordDump(const AJ_AuthRecord* record)
{
    AJ_ASSERT(record);
    AJ_Printf("Version %d Serial %d\n", record->version, record->serial);
    TermRecordDump(&record->term);
}

static void AJ_ManifestDump(const AJ_Manifest* manifest)
{
    AJ_ASSERT(manifest);
    RuleRecordsDump(&manifest->rules);
}

static AJ_Status AJ_X509Sign(X509Certificate* certificate, const AJ_KeyInfo* key)
{
    return AJ_ECDSASign(certificate->tbs.data, certificate->tbs.size, &key->key.privatekey, &certificate->signature);
}

static AJ_Status AJ_X509EncodeIdentityCertificateSig(X509Certificate* certificate, DER_Element* der)
{
    AJ_Status status = AJ_OK;
    size_t rpos = 383;
    size_t spos = 418;

    AJ_BigvalEncode(&certificate->signature.r, der->data + rpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->signature.s, der->data + spos, KEY_ECC_SZ);

    return status;
}

static AJ_Status AJ_X509EncodeMembershipCertificateSig(X509Certificate* certificate, DER_Element* der)
{
    AJ_Status status = AJ_OK;
    size_t rpos = 413;
    size_t spos = 448;

    AJ_BigvalEncode(&certificate->signature.r, der->data + rpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->signature.s, der->data + spos, KEY_ECC_SZ);

    return status;
}

static AJ_Status AJ_X509EncodeIdentityCertificateDER(X509Certificate* certificate, DER_Element* der)
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
    AJ_BigvalEncode(&certificate->keyinfo.key.publickey.x, der->data + xpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->keyinfo.key.publickey.y, der->data + ypos, KEY_ECC_SZ);

    certificate->tbs.data = der->data + 4;
    certificate->tbs.size = der->size - 4 - 12 - 75;

    return status;
}

static AJ_Status AJ_X509EncodeMembershipCertificateDER(X509Certificate* certificate, DER_Element* der)
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
    AJ_BigvalEncode(&certificate->keyinfo.key.publickey.x, der->data + xpos, KEY_ECC_SZ);
    AJ_BigvalEncode(&certificate->keyinfo.key.publickey.y, der->data + ypos, KEY_ECC_SZ);

    certificate->tbs.data = der->data + 4;
    certificate->tbs.size = der->size - 4 - 12 - 75;

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

static AJ_Status AJ_SecurityManagerInit()
{
    AJ_Status status;
    AJ_KeyInfo capub;
    AJ_KeyInfo caprv;
    AJ_KeyInfo sigpub;
    AJ_KeyInfo sigprv;
    AJ_GUID guid;
    X509Certificate certificate;
    DER_Element der;
    AJ_Cred cred;

    status = AJ_KeyInfoGetLocal(&capub, AJ_KEYINFO_ECDSA_CA_PUB);
    if (AJ_OK != status) {
        // Generate my certificate signing key
        status = AJ_KeyInfoGenerate(&capub, &caprv, KEY_USE_SIG);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&capub, AJ_KEYINFO_ECDSA_CA_PUB);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&caprv, AJ_KEYINFO_ECDSA_CA_PRV);
        AJ_ASSERT(AJ_OK == status);
    }
    status = AJ_KeyInfoGetLocal(&caprv, AJ_KEYINFO_ECDSA_CA_PRV);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("CA", (uint8_t*) &capub, KEYINFO_PUB_SZ);
    AJ_DumpBytes("CA", (uint8_t*) &caprv, KEYINFO_PRV_SZ);

    status = AJ_KeyInfoGetLocal(&sigpub, AJ_KEYINFO_ECDSA_SIG_PUB);
    if (AJ_OK != status) {
        // Generate my communiation signing key
        status = AJ_KeyInfoGenerate(&sigpub, &sigprv, KEY_USE_SIG);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&sigpub, AJ_KEYINFO_ECDSA_SIG_PUB);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_KeyInfoSetLocal(&sigprv, AJ_KEYINFO_ECDSA_SIG_PRV);
        AJ_ASSERT(AJ_OK == status);
    }
    status = AJ_KeyInfoGetLocal(&sigprv, AJ_KEYINFO_ECDSA_SIG_PRV);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("SIG", (uint8_t*) &sigpub, KEYINFO_PUB_SZ);
    AJ_DumpBytes("SIG", (uint8_t*) &sigprv, KEYINFO_PRV_SZ);

    status = AJ_GetLocalGUID(&guid);
    AJ_ASSERT(AJ_OK == status);
    cred.head.type = AJ_CERTIFICATE_IDN_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
    cred.head.id.size = sizeof (AJ_GUID);
    cred.head.id.data = (uint8_t*) &guid;

    status = AJ_GetCredential(&cred.head, NULL);
    if (AJ_OK != status) {
        // Issue myself a certificate
        certificate.type = IDENTITY_CERTIFICATE;
        memcpy(&certificate.keyinfo.key.publickey, &sigpub.key.publickey, sizeof (ecc_publickey));
        memcpy(&certificate.issuer, &guid, sizeof (AJ_GUID));
        memcpy(&certificate.subject, &guid, sizeof (AJ_GUID));
        status = AJ_X509EncodeIdentityCertificateDER(&certificate, &der);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_X509Sign(&certificate, &caprv);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_X509EncodeIdentityCertificateSig(&certificate, &der);
        AJ_ASSERT(AJ_OK == status);
        AJ_DumpBytes("DER", der.data, der.size);

        cred.body.expiration = 0xFFFFFFFF;
        cred.body.association.size = 0;
        cred.body.association.data = NULL;
        cred.body.data.size = der.size;
        cred.body.data.data = der.data;
        status = AJ_StoreCredential(&cred);
        AJ_ASSERT(AJ_OK == status);
        AJ_Free(der.data);
    }

    return status;
}

static AJ_GUID appGuid;
static AJ_KeyInfo* appPub = NULL;
static AJ_Manifest* appManifest = NULL;
static AJ_Status AJ_SecurityClaim(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    AJ_KeyInfo prv;
    AJ_KeyInfo pub;
    AJ_GUID issuer;
    X509Certificate certificate;
    DER_Element der;
    uint8_t fmt = CERT_FMT_X509_DER;
    const AJ_GUID* subject = AJ_GUID_Find(peer);

    AJ_InfoPrintf(("AJ_SecurityClaim(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    if (!appPub) {
        AJ_InfoPrintf(("AJ_SecurityClaim(bus=%p, peer=%s, session=%x): No public key form notify\n", bus, peer, session));
        return AJ_ERR_INVALID;
    }

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_CLAIM, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGetLocal(&pub, AJ_KEYINFO_ECDSA_CA_PUB);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoMarshal(&pub, &msg, NULL);
    AJ_ASSERT(AJ_OK == status);
    // Give it a random guid
    AJ_RandBytes(appGuid.val, sizeof (AJ_GUID));
    status = AJ_MarshalArgs(&msg, "ay", appGuid.val, sizeof (AJ_GUID));
    AJ_ASSERT(AJ_OK == status);

    // Issue an identity certificate
    status = AJ_GetLocalGUID(&issuer);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGetLocal(&prv, AJ_KEYINFO_ECDSA_CA_PRV);
    AJ_ASSERT(AJ_OK == status);

    certificate.type = IDENTITY_CERTIFICATE;
    memcpy(&certificate.issuer, &issuer, sizeof (AJ_GUID));
    memcpy(&certificate.subject, subject, sizeof (AJ_GUID));
    memcpy(&certificate.keyinfo.key.publickey, &appPub->key.publickey, sizeof (ecc_publickey));
    status = AJ_X509EncodeIdentityCertificateDER(&certificate, &der);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_X509Sign(&certificate, &prv);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_X509EncodeIdentityCertificateSig(&certificate, &der);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("DER", der.data, der.size);
    status = AJ_MarshalArgs(&msg, "(yay)", fmt, der.data, der.size);
    AJ_ASSERT(AJ_OK == status);

    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return status;
}

static AJ_Status AJ_SecurityClaimReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityClaimReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityClaimReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_GUID guild = { { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 } };
//static AJ_Identity idrecord = { AJ_SESSION_ENCRYPTED, AJ_ID_TYPE_ANY, NULL };
static AJ_Identity idrecord = { AJ_SESSION_AUTHENTICATED, AJ_ID_TYPE_GUILD, (uint8_t*) &guild, sizeof (AJ_GUID) };

static AJ_GUID admin;
static AJ_AuthRecord policy;
static AJ_AuthRecord authdata;

static void CreateTestPolicy(AJ_AuthRecord* record)
{
    record->version = 0;
    record->serial = 1;
    record->term.ids.num = 1;
    record->term.ids.id = &idrecord;
    //Use the app manifest
    record->term.rules.num = appManifest->rules.num;
    record->term.rules.rule = appManifest->rules.rule;
}

static void CreateAuthData(AJ_AuthRecord* record)
{
}

static AJ_Status AJ_SecurityInstallPolicy(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityInstallPolicy(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    if (!appManifest) {
        return AJ_ERR_INVALID;
    }

    status = AJ_GetLocalGUID(&admin);
    AJ_ASSERT(AJ_OK == status);
    CreateTestPolicy(&policy);
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
    AJ_AuthRecord record;

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
    AJ_GUID issuer;
    const AJ_GUID* subject = AJ_GUID_Find(peer);
    DER_Element der;
    uint8_t fmt = CERT_FMT_X509_DER;

    AJ_InfoPrintf(("AJ_SecurityInstallIdentity(bus=%p, peer=%s, session=%d)\n", bus, peer, session));

    AJ_ASSERT(subject);
    status = AJ_GetLocalGUID(&issuer);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGetLocal(&prv, AJ_KEYINFO_ECDSA_CA_PRV);
    AJ_ASSERT(AJ_OK == status);

    certificate.type = IDENTITY_CERTIFICATE;
    memcpy(&certificate.keyinfo.key.publickey, &appPub->key.publickey, sizeof (ecc_publickey));
    memcpy(&certificate.issuer, &issuer, sizeof (AJ_GUID));
    memcpy(&certificate.subject, subject, sizeof (AJ_GUID));
    status = AJ_X509EncodeIdentityCertificateDER(&certificate, &der);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("DER", der.data, der.size);
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
    AJ_GUID issuer;
    const AJ_GUID* subject = AJ_GUID_Find(peer);
    DER_Element der;
    uint8_t fmt = CERT_FMT_X509_DER;
    AJ_Arg container;

    AJ_InfoPrintf(("AJ_SecurityInstallMembership(bus=%p, peer=%s, session=%d)\n", bus, peer, session));

    AJ_ASSERT(subject);
    status = AJ_GetLocalGUID(&issuer);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_KeyInfoGetLocal(&prv, AJ_KEYINFO_ECDSA_CA_PRV);
    AJ_ASSERT(AJ_OK == status);

    certificate.type = MEMBERSHIP_CERTIFICATE;
    memcpy(&certificate.keyinfo.key.publickey, &appPub->key.publickey, sizeof (ecc_publickey));
    memcpy(&certificate.issuer, &issuer, sizeof (AJ_GUID));
    memset(&certificate.guild, 0x01, sizeof (AJ_GUID));
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
    CreateAuthData(&authdata);
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

static AJ_Status AJ_SecurityGetManifest(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityGetManifest(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_GET_MANIFEST, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return AJ_OK;
}

static AJ_Status AJ_SecurityGetManifestReply(AJ_Message* msg)
{
    AJ_Status status;

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityGetManifestReply(msg=%p): error=%s.\n", msg, msg->error));
        return AJ_ERR_SECURITY;
    } else {
        AJ_InfoPrintf(("AJ_SecurityGetManifestReply(msg=%p): OK\n", msg));
    }

    if (appManifest) {
        AJ_ManifestFree(appManifest);
        AJ_Free(appManifest);
        appManifest = NULL;
    }
    appManifest = (AJ_Manifest*) AJ_Malloc(sizeof (AJ_Manifest));
    status = AJ_ManifestUnmarshal(appManifest, msg);
    AJ_ASSERT(AJ_OK == status);
    AJ_ManifestDump(appManifest);

    return AJ_OK;
}

static AJ_Status AJ_SecurityReset(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityReset(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_RESET, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return AJ_OK;
}

static AJ_Status AJ_SecurityResetReply(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityResetReply(msg=%p): error=%s.\n", msg, msg->error));
    } else {
        AJ_InfoPrintf(("AJ_SecurityResetReply(msg=%p): OK\n", msg));
    }
    return AJ_OK;
}

static AJ_Status AJ_SecurityGetPublicKey(AJ_BusAttachment* bus, const char* peer, uint32_t session)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_SecurityGetPublicKey(bus=%p, peer=%s, session=%x)\n", bus, peer, session));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SECURITY_GET_PUBLICKEY, peer, session, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_DeliverMsg(&msg);
    AJ_ASSERT(AJ_OK == status);

    return AJ_OK;
}

static AJ_Status AJ_SecurityGetPublicKeyReply(AJ_Message* msg)
{
    AJ_Status status;
    AJ_KeyInfo pub;

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_SecurityGetPublicKeyReply(msg=%p): error=%s.\n", msg, msg->error));
        return AJ_ERR_SECURITY;
    } else {
        AJ_InfoPrintf(("AJ_SecurityGetPublicKeyReply(msg=%p): OK\n", msg));
    }

    status = AJ_KeyInfoUnmarshal(&pub, msg, NULL);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("KEY", (uint8_t*) &pub, sizeof (AJ_KeyInfo));

    return AJ_OK;
}

static AJ_Status AJ_SecurityNotifySignal(AJ_Message* msg)
{
    AJ_Status status;
    uint8_t claimstate;
    uint32_t serial;

    AJ_InfoPrintf(("AJ_SecurityNotifySignal(msg=%p)\n", msg));

    if (appPub) {
        AJ_Free(appPub);
        appPub = NULL;
    }
    appPub = (AJ_KeyInfo*) AJ_Malloc(sizeof (AJ_KeyInfo));

    status = AJ_KeyInfoUnmarshal(appPub, msg, NULL);
    AJ_ASSERT(AJ_OK == status);
    AJ_DumpBytes("KEYINFO", (uint8_t*) appPub, sizeof (AJ_KeyInfo));
    status = AJ_UnmarshalArgs(msg, "yu", &claimstate, &serial);
    AJ_ASSERT(AJ_OK == status);
    AJ_Printf("Application claim state  %d\n", claimstate);
    AJ_Printf("Application claim serial %x\n", serial);

    return AJ_OK;
}

static void PrintMenu()
{
    char s[] = {
        "=== Security Manager Menu ===\n"
        " 1. claim\n"
        " 2. installpolicy\n"
        " 3. removepolicy\n"
        " 4. getpolicy\n"
        " 5. installidentity\n"
        " 6. removeidentity\n"
        " 7. getidentity\n"
        " 8. installmembership\n"
        " 9. installmembershipauthdata\n"
        "10. removemembership\n"
        "11. getmanifest\n"
        "12. reset\n"
        "13. getpublickey\n"
        "14. exit\n"
        ">>> "
    };
    AJ_Printf("%s", s);
}

static AJ_Status CallInterface(AJ_BusAttachment* bus, uint32_t sessionId, const char* serviceName)
{
    int i;

    PrintMenu();
    if (!scanf("%d", &i)) {
        return AJ_ERR_SESSION_LOST;
    }

    switch (i) {
    case 1:
        AJ_SecurityClaim(bus, serviceName, sessionId);
        break;

    case 2:
        AJ_SecurityInstallPolicy(bus, serviceName, sessionId);
        break;

    case 3:
        AJ_SecurityRemovePolicy(bus, serviceName, sessionId);
        break;

    case 4:
        AJ_SecurityGetPolicy(bus, serviceName, sessionId);
        break;

    case 5:
        AJ_SecurityInstallIdentity(bus, serviceName, sessionId);
        break;

    case 6:
        AJ_SecurityRemoveIdentity(bus, serviceName, sessionId);
        break;

    case 7:
        AJ_SecurityGetIdentity(bus, serviceName, sessionId);
        break;

    case 8:
        AJ_SecurityInstallMembership(bus, serviceName, sessionId);
        break;

    case 9:
        AJ_SecurityInstallMembershipAuthData(bus, serviceName, sessionId);
        break;

    case 10:
        AJ_SecurityRemoveMembership(bus, serviceName, sessionId);
        break;

    case 11:
        AJ_SecurityGetManifest(bus, serviceName, sessionId);
        break;

    case 12:
        AJ_SecurityReset(bus, serviceName, sessionId);
        break;

    case 13:
        AJ_SecurityGetPublicKey(bus, serviceName, sessionId);
        break;

    default:
        return AJ_ERR_SESSION_LOST;
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
    uint32_t suites[3];
    size_t numsuites = 0;
    uint8_t clearkeys = FALSE;
    uint8_t running = TRUE;
    const char* rule = "interface='org.alljoyn.Security.PermissionMgmt.Notification',sessionless='t'";

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
        }
    }

    if (!serviceName) {
        AJ_Printf("Service required\n");
        return 1;
    }
#endif
#endif

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();
    AJ_SecurityManagerInit();

    while (running) {
        AJ_Message msg;

        if (!connected) {
#ifndef NGNS
            status = AJ_StartClient(&bus, NULL, CONNECT_TIMEOUT, FALSE, serviceName, ManagementPort, &sessionId, NULL);
#else
            status = AJ_StartClientByInterface(&bus, NULL, CONNECT_TIMEOUT, FALSE, testInterfaceNames, &sessionId, serviceName, NULL);
#endif
            if (status == AJ_OK) {
                AJ_Printf("StartClient returned %d, sessionId=%u, serviceName=%s\n", status, sessionId, serviceName);
                AJ_Printf("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus));
                connected = TRUE;
                status = AJ_BusSetSignalRule(&bus, rule, AJ_BUS_SIGNAL_ALLOW);
#if defined(SECURE_INTERFACE) || defined(SECURE_OBJECT)
                AJ_BusEnableSecurity(&bus, suites, ArraySize(suites));
                AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
                if (clearkeys) {
                    status = AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
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
                AJ_InfoPrintf(("Waiting for message...\n"));
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
                        status = CallInterface(&bus, sessionId, serviceName);
                    } else {
                        AJ_Printf("SetLinkTimeout failed %d\n", disposition);
                    }
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
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_POLICY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_POLICY)\n"));
                status = AJ_SecurityInstallPolicyReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_POLICY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_POLICY)\n"));
                status = AJ_SecurityRemovePolicyReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_POLICY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_POLICY)\n"));
                status = AJ_SecurityGetPolicyReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_IDENTITY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_INSTALL_IDENTITY)\n"));
                status = AJ_SecurityInstallIdentityReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_IDENTITY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_REMOVE_IDENTITY)\n"));
                status = AJ_SecurityRemoveIdentityReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_IDENTITY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_GET_IDENTITY)\n"));
                status = AJ_SecurityGetIdentityReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_MEMBERSHIP):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_MEMBERSHIP)\n"));
                status = AJ_SecurityInstallMembershipReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_AUTHDATA):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_INSTALL_AUTHDATA)\n"));
                status = AJ_SecurityInstallMembershipAuthDataReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_MEMBERSHIP):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_REMOVE_MEMBERSHIP)\n"));
                status = AJ_SecurityRemoveMembershipReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_MANIFEST):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_MANIFEST)\n"));
                status = AJ_SecurityGetManifestReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_RESET):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_RESET)\n"));
                status = AJ_SecurityResetReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_PUBLICKEY):
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_REPLY_ID(AJ_METHOD_SECURITY_GET_PUBLICKEY)\n"));
                status = AJ_SecurityGetPublicKeyReply(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
                status = CallInterface(&bus, sessionId, serviceName);
                break;

            case AJ_SIGNAL_SECURITY_NOTIFY_CONFIG:
                AJ_InfoPrintf(("AJ_HandleMessage(): AJ_SIGNAL_SECURITY_NOTIFY_CONFIG\n"));
                status = AJ_SecurityNotifySignal(&msg);
                if (AJ_OK != status) {
                    return 1;
                }
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

        //if ((status == AJ_ERR_SESSION_LOST) || (status == AJ_ERR_READ) || (status == AJ_ERR_LINK_DEAD) || (status == AJ_ERR_INVALID)) {
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
