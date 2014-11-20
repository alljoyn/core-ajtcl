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
#define AJ_MODULE KEYEXCHANGE

#include "aj_target.h"
#include "aj_debug.h"
#include "aj_keyexchange.h"
#include "aj_crypto_ecc.h"
#include "aj_creds.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgKEYEXCHANGE = 0;
#endif

/*
 * ECC curve paramaters (version number)
 * In this code, we only support NIST P256
 */
#define ECC_NIST_P256 0

static AJ_Status ECDHE_Init(AJ_SHA256_Context* hash);
static AJ_Status ECDHE_Marshal(AJ_Message* msg);
static AJ_Status ECDHE_Unmarshal(AJ_Message* msg);
static void ECDHE_GetSecret(uint8_t** secret, size_t* secretlen);

AJ_KeyExchange AJ_KeyExchangeECDHE = {
    ECDHE_Init,
    ECDHE_Marshal,
    ECDHE_Unmarshal,
    ECDHE_GetSecret
};

typedef struct _AJ_ECDHEContext {
    AJ_KeyInfo pub;
    AJ_KeyInfo prv;
    uint8_t secret[SHA256_DIGEST_LENGTH];
    AJ_SHA256_Context* hash;
} AJ_ECDHEContext;


static AJ_ECDHEContext ecdhectx;

static AJ_Status ECDHE_Init(AJ_SHA256_Context* hash)
{
    ecdhectx.hash = hash;
    return AJ_KeyInfoGenerate(&ecdhectx.pub, &ecdhectx.prv, KEY_USE_SIG);
}

static AJ_Status ECDHE_Marshal(AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_ECDHE_Marshal(msg=%p)\n", msg));

    status = AJ_MarshalVariant(msg, "(yv)");
    status = AJ_KeyInfoMarshal(&ecdhectx.pub, msg, ecdhectx.hash);

    return status;
}

static AJ_Status ECDHE_Unmarshal(AJ_Message* msg)
{
    AJ_Status status;
    AJ_KeyInfo pub;
    char* variant;
    ecc_secret sec;
    uint8_t buf[KEY_ECC_SEC_SZ];
    AJ_SHA256_Context ctx;

    AJ_InfoPrintf(("AJ_ECDHE_Unmarshal(msg=%p)\n", msg));

    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(yv)", 4)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_KeyInfoUnmarshal(&pub, msg, ecdhectx.hash);
    if (AJ_OK != status) {
        return status;
    }
    if (KEY_USE_SIG != pub.use) {
        return AJ_ERR_SECURITY;
    }

    status = AJ_GenerateShareSecret(&pub.key.publickey, &ecdhectx.prv.key.privatekey, &sec);
    if (AJ_OK != status) {
        return status;
    }
    AJ_BigvalEncode(&sec.x, buf, KEY_ECC_SZ);
    AJ_BigvalEncode(&sec.y, buf + KEY_ECC_SZ, KEY_ECC_SZ);

    //Hash the point
    AJ_SHA256_Init(&ctx);
    AJ_SHA256_Update(&ctx, (const uint8_t*) buf, sizeof (buf));
    AJ_SHA256_Final(&ctx, ecdhectx.secret);

    return status;
}

static void ECDHE_GetSecret(uint8_t** secret, size_t* secretlen)
{
    AJ_InfoPrintf(("AJ_ECDHE_GetSecret(secret=%p, secretlen=%p)\n", secret, secretlen));

    *secret = ecdhectx.secret;
    *secretlen = sizeof (ecdhectx.secret);
}
