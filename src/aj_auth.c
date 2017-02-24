/**
 * @file   PIN code authentication mechanism
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
 *    
 *    SPDX-License-Identifier: Apache-2.0
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *    
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *    
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
******************************************************************************/

#include "aj_target.h"
#include "aj_status.h"
#include "aj_sasl.h"
#include "aj_auth.h"
#include "aj_guid.h"
#include "aj_creds.h"
#include "aj_util.h"
#include "aj_crypto.h"
#include "aj_debug.h"

static AJ_AuthResult AuthResponse(const char* inStr, char* outStr, uint32_t outLen);
static AJ_AuthResult AuthChallenge(const char* inStr, char* outStr, uint32_t outLen);
static AJ_Status AuthInit(uint8_t role, AJ_AuthPwdFunc pwdFunc);
static AJ_Status AuthFinal(const AJ_GUID* peerGuid);

const AJ_AuthMechanism AJ_AuthPin = {
    AuthInit,
    AuthChallenge,
    AuthResponse,
    AuthFinal,
    "ALLJOYN_PIN_KEYX"
};
/*
 * Length of the nonce.
 */
#define NONCE_LEN     28

/*
 * Length of the verifier string
 */
#define VERIFIER_LEN  12

/*
 * Length of the master secret
 */
#define MASTER_SECRET_LEN 24

typedef struct _PinAuthContext {
    AJ_AuthPwdFunc pwdFunc;
    uint8_t state;
    uint8_t success;
    /*
     * The lifetimes of the nonce and secret don't overlap so they can use the same memory.
     */
    union {
        uint8_t masterSecret[MASTER_SECRET_LEN];
        uint8_t nonce[NONCE_LEN];
    };
} PinAuthContext;

/*
 * This is only 36 bytes - probably not worth malloc'ing
 */
static PinAuthContext context;

#ifdef AUTH_DEBUG
static char* Hex(const uint8_t* buf, size_t len)
{
    static char hex[128];
    AJ_RawToHex(buf, len, hex, sizeof(hex), FALSE);
    return hex;
}
#endif

static AJ_Status ComputeVerifier(const char* label, char* buffer, size_t bufLen)
{
    AJ_Status status;
    const uint8_t* data[2];
    uint8_t lens[2];

    data[0] = context.masterSecret;
    lens[0] = MASTER_SECRET_LEN;
    data[1] = (uint8_t*)label;
    lens[1] = (uint8_t)strlen(label);

    status = AJ_Crypto_PRF(data, lens, ArraySize(data), (uint8_t*)buffer, VERIFIER_LEN);
#ifdef AUTH_DEBUG
    AJ_Printf("ComputeVerifier(%s): %s\n", label, Hex((uint8_t*)buffer, VERIFIER_LEN));
#endif
    if (status == AJ_OK) {
        status = AJ_RawToHex((uint8_t*) buffer, VERIFIER_LEN, buffer, bufLen, FALSE);
    }
    return status;
}

/*
 * Compute the key exchange key from the server and client nonces and the pin code.
 */
static AJ_Status ComputeMS(const uint8_t* nonce)
{
    AJ_Status status;
    uint8_t pwd[ADHOC_LEN];
    const uint8_t* data[4];
    uint8_t lens[4];
    uint32_t pwdLen = context.pwdFunc(pwd, sizeof(pwd));

    if (pwdLen == 0) {
        return AJ_ERR_SECURITY;
    }
    data[0] = pwd;
    lens[0] = pwdLen;
    data[1] = context.nonce;
    lens[1] = NONCE_LEN;
    data[2] = nonce;
    lens[2] = NONCE_LEN;
    data[3] = (uint8_t*)"master secret";
    lens[3] = 13;
    /*
     * Use the PRF function to compute the master secret
     */
    status = AJ_Crypto_PRF(data, lens, ArraySize(data), context.masterSecret, MASTER_SECRET_LEN);
#ifdef AUTH_DEBUG
    AJ_Printf("MasterSecret: %s\n", Hex(context.masterSecret, MASTER_SECRET_LEN));
#endif
    return status;
}

static AJ_AuthResult AuthResponse(const char* inStr, char* outStr, uint32_t outLen)
{
    AJ_AuthResult result;
    AJ_Status status = AJ_OK;
    uint8_t* nonce;
    int32_t pos;

    /*
     * Responder begins by sending a nonce.
     */
    if (!inStr) {
        AJ_RandBytes(context.nonce, NONCE_LEN);
        AJ_RawToHex(context.nonce, NONCE_LEN, outStr, outLen, FALSE);
        return AJ_AUTH_STATUS_CONTINUE;
    }
    /*
     * Server sends a random nonce concatenated with a verifier string.
     */
    pos = AJ_StringFindFirstOf(inStr, ":");
    if (pos < 0) {
        /*
         * String is incorrectly formatted - fail the authentication
         */
        return AJ_AUTH_STATUS_FAILURE;
    }
    /*
     * We should be able to use outStr to convert the nonce
     */
    if (outLen < NONCE_LEN) {
        status = AJ_ERR_RESOURCES;
    } else {
        nonce = (uint8_t*)outStr;
        status = AJ_HexToRaw(inStr, pos, nonce, NONCE_LEN);
    }
    /*
     * Compute the master secret
     */
    if (status == AJ_OK) {
        status = ComputeMS(nonce);
    }
    if (status == AJ_OK) {
        status = ComputeVerifier("server finish", outStr, outLen);
    }
    /*
     * Check that the computed verifier matches the one we received
     */
    if (status == AJ_OK) {
        if (strcmp(inStr + pos + 1, outStr) == 0) {
            ComputeVerifier("client finish", outStr, outLen);
            result = AJ_AUTH_STATUS_SUCCESS;
            context.success = TRUE;
        } else {
            result = AJ_AUTH_STATUS_RETRY;
        }
    } else {
        result = AJ_AUTH_STATUS_FAILURE;
    }
    return result;
}

static AJ_AuthResult AuthChallenge(const char* inStr, char* outStr, uint32_t outLen)
{
    AJ_AuthResult result = AJ_AUTH_STATUS_FAILURE;
    AJ_Status status;

    if (context.state == 0) {
        /*
         * Client sent a nonce
         */
        status = AJ_HexToRaw(inStr, 0, context.nonce, NONCE_LEN);
        /*
         * Get server's nonce
         */
        if (outLen < NONCE_LEN) {
            status = AJ_ERR_RESOURCES;
        } else {
            AJ_RandBytes((uint8_t*)outStr, NONCE_LEN);
            /*
             * Compute the master secret
             */
            if (status == AJ_OK) {
                status = ComputeMS((uint8_t*)outStr);
            }
            /*
             * Write nonce to the output string
             */
            if (status == AJ_OK) {
                status = AJ_RawToHex((uint8_t*) outStr, NONCE_LEN, outStr, outLen - (1 + VERIFIER_LEN), FALSE);
            }
            /*
             * Append verifier to the nonce
             */
            if (status == AJ_OK) {
                size_t len = strlen(outStr);
                outStr[len++] = ':';
                outStr[len] = '\0';
                ComputeVerifier("server finish", outStr + len, outLen - len);
                result = AJ_AUTH_STATUS_CONTINUE;
            }
        }
        context.state = 1;
    } else {
        /*
         * Check the client's verifier (borrow the out buffer)
         */
        status = ComputeVerifier("client finish", outStr, outLen);
        if (status == AJ_OK) {
            if (strcmp(inStr, outStr) == 0) {
                result = AJ_AUTH_STATUS_SUCCESS;
                context.success = TRUE;
            } else {
                result = AJ_AUTH_STATUS_RETRY;
            }
        }
        *outStr = '\0';
        context.state = 0;
    }
    if (status != AJ_OK) {
        result = AJ_AUTH_STATUS_FAILURE;
    }
    return result;
}

AJ_Status AuthInit(uint8_t role, AJ_AuthPwdFunc pwdFunc)
{
    if (pwdFunc) {
        memset(&context, 0, sizeof(context));
        context.pwdFunc = pwdFunc;
        return AJ_OK;
    } else {
        /*
         * Must have a password function
         */
        return AJ_ERR_SECURITY;
    }
}

static AJ_Status AuthFinal(const AJ_GUID* peerGuid)
{
    AJ_Status status = AJ_OK;

    if (peerGuid) {
        /*
         * If the authentication was succesful write the credentials for the authenticated peer to
         * NVRAM otherwise delete any stale credentials that might be stored.
         */
        if (context.success) {
            AJ_PeerCred cred;
            AJ_ASSERT(sizeof(cred.secret) == MASTER_SECRET_LEN);
            memcpy(&cred.guid, peerGuid, sizeof(AJ_GUID));
            memcpy(&cred.secret, context.masterSecret, MASTER_SECRET_LEN);
            status = AJ_StoreCredential(&cred);
        } else {
            status = AJ_DeleteCredential(peerGuid);
        }
    }
    memset(&context, 0, sizeof(context));
    return status;
}