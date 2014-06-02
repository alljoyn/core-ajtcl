/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012-2014 AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE PEER

#include "aj_target.h"
#include "aj_peer.h"
#include "aj_bus.h"
#include "aj_msg.h"
#include "aj_util.h"
#include "aj_guid.h"
#include "aj_creds.h"
#include "aj_std.h"
#include "aj_auth.h"
#include "aj_crypto.h"
#include "aj_crypto_sha2.h"
#include "aj_debug.h"
#include "aj_config.h"
#include "aj_keyexchange.h"
#include "aj_keyauthentication.h"
#include "aj_cert.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgPEER = 0;
#endif

/*
 * Version number of the key generation algorithm.
 */
#define MIN_KEYGEN_VERSION  0x00
#define MAX_KEYGEN_VERSION  0x01

/*
 * The base authentication version number
 */
#define MIN_AUTH_VERSION  0x0001
#define MAX_AUTH_VERSION  0x0002

#define REQUIRED_AUTH_VERSION  (((uint32_t)MAX_AUTH_VERSION << 16) | MIN_KEYGEN_VERSION)

#define AES_KEY_LEN   16

typedef AJ_Status (*AJ_CryptoPRF)(const uint8_t** inputs,
                                  const uint8_t* lengths,
                                  uint32_t count,
                                  uint8_t* out,
                                  uint32_t outLen);

static AJ_Status ComputeMasterSecret(uint8_t* secret, size_t secretlen);
static AJ_Status SaveMasterSecret(const AJ_GUID* peerGuid, uint32_t expiration);
static AJ_Status ExchangeSuites(AJ_Message* msg);
static AJ_Status KeyExchange(AJ_Message* msg);
static AJ_Status KeyAuthentication(AJ_Message* msg);
static AJ_Status GenSessionKey(AJ_Message* msg);
extern void U32ToU8(uint32_t* u32, size_t len, uint8_t* u8);

typedef enum {
    SASL_HANDSHAKE,
    ALLJOYN_HANDSHAKE
} HandshakeType;

typedef struct _VersionContext {
    HandshakeType handshakeType;     /* Handshake type */
    AJ_CryptoPRF PRF;                /* PRF function */
} VersionContext;

typedef struct _AuthContext {
    AJ_BusAuthPeerCallback callback; /* Callback function to report completion */
    void* cbContext;                 /* Context to pass to the callback function */
    const AJ_GUID* peerGuid;         /* GUID pointer for the currently authenticating peer */
    const char* peerName;            /* Name of the peer being authenticated */
    AJ_Time timer;                   /* Timer for detecting failed authentication attempts */
} AuthContext;

typedef enum {
    AJ_AUTH_NONE,
    AJ_AUTH_EXCHANGED,
    AJ_AUTH_SUCCESS
} HandshakeState;

typedef struct _HandshakeContext {
    HandshakeState state;
    AJ_KeyExchange* keyexchange;
    AJ_KeyAuthentication* keyauthentication;
    uint8_t mastersecret[AJ_MASTER_SECRET_LEN];
    AJ_SHA256_Context hash;
    uint32_t* suites;
    size_t numsuites;
    uint32_t suite;
} HandshakeContext;

typedef struct _SessionContext {
    char nonce[2 * AJ_NONCE_LEN + 1];   /* Nonce as ascii hex */
} SessionContext;

static VersionContext versionContext;
static AuthContext authContext;
static HandshakeContext handshakeContext;
static SessionContext sessionContext;

static AJ_Status SetAuthVersion(uint32_t version)
{
    AJ_Status status = AJ_OK;

    /*
     * Set handshake type from version
     */
    switch (version >> 16) {
    case 1:
        /*
         * Deprecated SASL handshake
         */
        status = AJ_ERR_INVALID;
        break;

    default:
        versionContext.handshakeType = ALLJOYN_HANDSHAKE;
        AJ_InfoPrintf(("AJ_PeerAuthVersion(): ALLJOYN\n"));
        break;
    }
    /*
     * Set key generation function from version
     */
    switch (version & 0xff) {
    case 1:
        versionContext.PRF = &AJ_Crypto_PRF;
        break;

    default:
        versionContext.PRF = &AJ_Crypto_PRF_SHA256;
        break;
    }

    return status;
}

static AJ_Status SetCipherSuite(AJ_BusAttachment* bus, uint32_t suite)
{
    switch (suite) {
    case AUTH_SUITE_ECDHE_NULL:
        handshakeContext.keyexchange = &AJ_KeyExchangeECDHE;
        handshakeContext.keyauthentication = &AJ_KeyAuthenticationNULL;
        break;

    case AUTH_SUITE_ECDHE_PSK:
        handshakeContext.keyexchange = &AJ_KeyExchangeECDHE;
        handshakeContext.keyauthentication = &AJ_KeyAuthenticationPSK;
        AJ_PSK_SetPwdCallback(bus->pwdCallback);
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        handshakeContext.keyexchange = &AJ_KeyExchangeECDHE;
        handshakeContext.keyauthentication = &AJ_KeyAuthenticationECDSA;
        break;

    default:
        handshakeContext.keyexchange = NULL;
        handshakeContext.keyauthentication = NULL;
        return AJ_ERR_INVALID;
        break;
    }
    return AJ_OK;
}

/**
 * check the credential's expiry
 * @return 1 when the credential expires
 *         0 when the credential do not expire
 *         2 when it can't be determine whether the credential expires because
 *              no clock is available
 */
static uint8_t checkCredExpiration(AJ_PeerCred* cred)
{
    AJ_Time now;

    AJ_InitTimer(&now);
    if (now.seconds == 0) {
        /* don't know the current time so can't check the credential expriy */
        return 2;
    }

    if (cred->expiration > now.seconds) {
        return 0;
    }

    return 1; /* expires */
}

static uint32_t GetAcceptableVersion(uint32_t srcV)
{
    uint16_t authV = srcV >> 16;
    uint16_t keyV = srcV & 0xFFFF;

    if ((authV < MIN_AUTH_VERSION) || (authV > MAX_AUTH_VERSION)) {
        return 0;
    }
    if ((keyV < MIN_KEYGEN_VERSION) || (keyV > MAX_KEYGEN_VERSION)) {
        return 0;
    }

    if (authV < MAX_AUTH_VERSION) {
        return srcV;
    }
    if (keyV < MAX_KEYGEN_VERSION) {
        return srcV;
    }
    return REQUIRED_AUTH_VERSION;
}

static AJ_Status KeyGen(const char* peerName, uint8_t role, const char* nonce1, const char* nonce2, uint8_t* outBuf, uint32_t len)
{
    AJ_Status status;
    const uint8_t* data[4];
    uint8_t lens[4];
    AJ_PeerCred* cred;
    const AJ_GUID* peerGuid = AJ_GUID_Find(peerName);
    uint8_t expiryStatus;

    AJ_InfoPrintf(("KeyGen(peerName=\"%s\", role=%d., nonce1=\"%s\", nonce2=\"%s\", outbuf=0x%p, len=%d.)\n",
                   peerName, role, nonce1, nonce2, outBuf, len));

    if (NULL == peerGuid) {
        AJ_ErrPrintf(("KeyGen(): AJ_ERR_UNEXPECTED\n"));
        return AJ_ERR_UNEXPECTED;
    }

    status = AJ_GetPeerCredential(peerGuid, &cred);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("KeyGen(): AJ_ERR_NO_MATCH\n"));
        return AJ_ERR_NO_MATCH;
    }
    /* check the secret expiry */
    expiryStatus = checkCredExpiration(cred);
    if (expiryStatus == 1) {
        /* secret expired */
        AJ_DeletePeerCredential(peerGuid);
        AJ_ErrPrintf(("KeyGen(): Secret expired\n"));
        AJ_FreeCredential(cred);
        return AJ_ERR_KEY_EXPIRED;
    }
    data[0] = cred->data;
    lens[0] = (uint32_t) cred->dataLen;

    data[1] = (uint8_t*)"session key";
    lens[1] = 11;
    data[2] = (uint8_t*)nonce1;
    lens[2] = (uint32_t)strlen(nonce1);
    data[3] = (uint8_t*)nonce2;
    lens[3] = (uint32_t)strlen(nonce2);

    /*
     * We use the outBuf to store both the key and verifier string.
     * Check that there is enough space to do so.
     */
    if (len < (AES_KEY_LEN + AJ_VERIFIER_LEN)) {
        AJ_ErrPrintf(("KeyGen(): AJ_ERR_RESOURCES\n"));
        AJ_FreeCredential(cred);
        return AJ_ERR_RESOURCES;
    }

    status = versionContext.PRF(data, lens, ArraySize(data), outBuf, AES_KEY_LEN + AJ_VERIFIER_LEN);
    /*
     * Store the session key and compose the verifier string.
     */
    if (status == AJ_OK) {
        status = AJ_SetSessionKey(peerName, outBuf, role);
    }
    if (status == AJ_OK) {
        memmove(outBuf, outBuf + AES_KEY_LEN, AJ_VERIFIER_LEN);
        status = AJ_RawToHex(outBuf, AJ_VERIFIER_LEN, (char*) outBuf, len, FALSE);
    }
    AJ_InfoPrintf(("KeyGen Verifier = %s.\n", outBuf));
    AJ_FreeCredential(cred);
    return status;
}

static void HandshakeComplete(AJ_Status status)
{
    AJ_InfoPrintf(("HandshakeComplete(status=%d.)\n", status));

    if (authContext.callback) {
        authContext.callback(authContext.cbContext, status);
    }
    memset(&authContext, 0, sizeof(AuthContext));
    if (handshakeContext.suites) {
        AJ_Free(handshakeContext.suites);
    }
    memset(&handshakeContext, 0, sizeof(HandshakeContext));
}

static AJ_Status ComputeMasterSecret(uint8_t* secret, size_t secretlen)
{
    AJ_Status status;
    const uint8_t* data[2];
    uint8_t lens[2];

    AJ_InfoPrintf(("ComputeMasterSecret(secret=0x%p)\n", secret));

    data[0] = secret;
    lens[0] = secretlen;
    data[1] = (uint8_t*)"master secret";
    lens[1] = 13;

    status = versionContext.PRF(data, lens, ArraySize(data), handshakeContext.mastersecret, AJ_MASTER_SECRET_LEN);

    return status;
}

static AJ_Status SaveMasterSecret(const AJ_GUID* peerGuid, uint32_t expiration)
{
    AJ_Status status;

    AJ_InfoPrintf(("SaveMasterSecret(peerGuid=0x%p, expiration=%d)\n", peerGuid, expiration));

    if (peerGuid) {
        /*
         * If the authentication was succesful write the credentials for the authenticated peer to
         * NVRAM otherwise delete any stale credentials that might be stored.
         */
        if (AJ_AUTH_SUCCESS == handshakeContext.state) {
            status = AJ_StorePeerSecret(peerGuid, handshakeContext.mastersecret, AJ_MASTER_SECRET_LEN, expiration);
        } else {
            AJ_InfoPrintf(("SaveMasterSecret(peerGuid=0x%p, expiration=%d): Invalid state\n", peerGuid, expiration));
            status = AJ_DeletePeerCredential(peerGuid);
        }
    } else {
        status = AJ_ERR_SECURITY;
    }

    return status;
}

static AJ_Status HandshakeTimeout() {
    if (AJ_GetElapsedTime(&authContext.timer, TRUE) >= AJ_MAX_AUTH_TIME) {
        AJ_InfoPrintf(("AJ_HandshakeTimeout(): AJ_ERR_TIMEOUT\n"));
        HandshakeComplete(AJ_ERR_TIMEOUT);
        return AJ_ERR_TIMEOUT;
    }
    return AJ_OK;
}

static AJ_Status HandshakeValid(const AJ_GUID* peerGuid)
{
    /*
     * Handshake not yet started
     */
    if (!authContext.peerGuid) {
        AJ_InfoPrintf(("AJ_HandshakeValid(peerGuid=0x%p): Invalid peer guid\n", peerGuid));
        return AJ_ERR_SECURITY;
    }
    /*
     * Handshake timed out
     */
    if (AJ_OK != HandshakeTimeout()) {
        AJ_InfoPrintf(("AJ_HandshakeValid(peerGuid=0x%p): Handshake timed out\n", peerGuid));
        return AJ_ERR_TIMEOUT;
    }
    /*
     * Handshake call from different peer
     */
    if (!peerGuid || (peerGuid != authContext.peerGuid)) {
        AJ_InfoPrintf(("AJ_HandshakeValid(peerGuid=0x%p): Invalid peer guid\n", peerGuid));
        return AJ_ERR_RESOURCES;
    }

    return AJ_OK;
}

AJ_Status AJ_PeerAuthenticate(AJ_BusAttachment* bus, const char* peerName, AJ_PeerAuthenticateCallback callback, void* cbContext)
{
#ifndef NO_AUTH_PIN_KEYX
    AJ_Status status;
    AJ_Message msg;
    char guidStr[33];
    AJ_GUID localGuid;
    uint32_t version = REQUIRED_AUTH_VERSION;

    AJ_InfoPrintf(("PeerAuthenticate(bus=0x%p, peerName=\"%s\", callback=0x%p, cbContext=0x%p)\n",
                   bus, peerName, callback, cbContext));

    /*
     * If handshake in progress and not timed-out
     */
    if (authContext.peerGuid) {
        status = HandshakeTimeout();
        if (AJ_ERR_TIMEOUT != status) {
            AJ_InfoPrintf(("PeerAuthenticate(): Handshake in progress\n"));
            return AJ_ERR_RESOURCES;
        }
    }

    /*
     * No handshake in progress or previous timed-out
     */
    memset(&authContext, 0, sizeof(AuthContext));
    memset(&handshakeContext, 0, sizeof(HandshakeContext));
    authContext.callback = callback;
    authContext.cbContext = cbContext;
    authContext.peerName = peerName;
    AJ_InitTimer(&authContext.timer);
    /*
     * Kick off authentication with an ExchangeGUIDS method call
     */
    AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_EXCHANGE_GUIDS, peerName, 0, AJ_NO_FLAGS, AJ_CALL_TIMEOUT);
    AJ_GetLocalGUID(&localGuid);
    AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    AJ_MarshalArgs(&msg, "su", guidStr, version);
    return AJ_DeliverMsg(&msg);
#else
    return AJ_OK;
#endif
}

AJ_Status AJ_PeerHandleExchangeGUIDs(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    char guidStr[33];
    uint32_t version;
    char* str;
    AJ_GUID remoteGuid;
    AJ_GUID localGuid;

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=0x%p, reply=0x%p)\n", msg, reply));

    /*
     * If handshake in progress and not timed-out
     */
    if (authContext.peerGuid) {
        status = HandshakeTimeout();
        if (AJ_ERR_TIMEOUT != status) {
            AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=0x%p, reply=0x%p): Handshake in progress\n", msg, reply));
            return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
        }
    }

    /*
     * No handshake in progress or previous timed-out
     */
    memset(&authContext, 0, sizeof(AuthContext));
    memset(&handshakeContext, 0, sizeof(HandshakeContext));
    AJ_InitTimer(&authContext.timer);

    status = AJ_UnmarshalArgs(msg, "su", &str, &version);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=0x%p, reply=0x%p): Unmarshal error\n", msg, reply));
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = AJ_GUID_FromString(&remoteGuid, str);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=0x%p, reply=0x%p): Invalid GUID\n", msg, reply));
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = AJ_GUID_AddNameMapping(&remoteGuid, msg->sender, NULL);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=0x%p, reply=0x%p): Add name mapping error\n", msg, reply));
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    authContext.peerGuid = AJ_GUID_Find(msg->sender);
    /*
     * We are not currently negotiating versions so we tell the peer what version we require.
     */
    version = GetAcceptableVersion(version);
    if (0 == version) {
        version = REQUIRED_AUTH_VERSION;
    }
    AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=0x%p, reply=0x%p): Version %x\n", msg, reply, version));
    status = SetAuthVersion(version);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=0x%p, reply=0x%p): Invalid version\n", msg, reply));
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    AJ_MarshalReplyMsg(msg, reply);
    AJ_GetLocalGUID(&localGuid);
    AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    return AJ_MarshalArgs(reply, "su", guidStr, version);
}

AJ_Status AJ_PeerHandleExchangeGUIDsReply(AJ_Message* msg)
{
    AJ_Status status;
    const char* guidStr;
    AJ_GUID remoteGuid;
    uint32_t version;
    AJ_PeerCred* cred;

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p): error=%s.\n", msg, msg->error));
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else {
            status = AJ_ERR_SECURITY;
            HandshakeComplete(status);
        }
        return status;
    }

    /*
     * If handshake in progress and not timed-out
     */
    if (authContext.peerGuid) {
        status = HandshakeTimeout();
        if (AJ_ERR_TIMEOUT != status) {
            AJ_ErrPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p): Handshake in progress\n", msg));
            return AJ_ERR_RESOURCES;
        }
    }

    status = AJ_UnmarshalArgs(msg, "su", &guidStr, &version);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p): Unmarshal error\n", msg));
        return AJ_ERR_SECURITY;
    }
    version = GetAcceptableVersion(version);
    if (0 == version) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p): Invalid version\n", msg));
        return AJ_ERR_SECURITY;
    }
    status = SetAuthVersion(version);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p): Invalid version\n", msg));
        return AJ_ERR_SECURITY;
    }
    status = AJ_GUID_FromString(&remoteGuid, guidStr);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p): Invalid GUID\n", msg));
        return AJ_ERR_SECURITY;
    }
    /*
     * Two name mappings to add, the well known name, and the unique name from the message.
     */
    status = AJ_GUID_AddNameMapping(&remoteGuid, msg->sender, authContext.peerName);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=0x%p): Add name mapping error\n", msg));
        return AJ_ERR_SECURITY;
    }
    /*
     * Remember which peer is being authenticated
     */
    authContext.peerGuid = AJ_GUID_Find(msg->sender);

    /*
     * If we have a mastersecret stored - use it
     */
    status = AJ_GetPeerCredential(authContext.peerGuid, &cred);
    if (AJ_OK == status) {
        uint8_t expiryStatus = checkCredExpiration(cred);
        if ((expiryStatus == 0)  || (expiryStatus == 2)) {
            /* secret not expired or time unknown */
            handshakeContext.state = AJ_AUTH_SUCCESS;
            status = GenSessionKey(msg);
        }
        AJ_FreeCredential(cred);
        return status;
    }

    switch (versionContext.handshakeType) {
    case ALLJOYN_HANDSHAKE:
        /*
         * Start the ALLJOYN conversation
         */
        status = ExchangeSuites(msg);
        break;

    default:
        status = AJ_ERR_INVALID;
        break;
    }
    if (AJ_OK != status) {
        HandshakeComplete(status);
    }
    return status;
}

static AJ_Status ExchangeSuites(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message call;

    AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p)\n", msg));

    AJ_SHA256_Init(&handshakeContext.hash);

    /*
     * Send suites
     */
    if (!msg->bus->numsuites) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): No suites available\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_EXCHANGE_SUITES, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    status = AJ_MarshalArgs(&call, "au", msg->bus->suites, msg->bus->numsuites * sizeof (uint32_t));
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): Marshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    return AJ_DeliverMsg(&call);
}

AJ_Status AJ_PeerHandleExchangeSuites(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    uint32_t* suites;
    size_t numsuites;
    size_t i, j;
    uint32_t* common;
    size_t numcommon;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=0x%p, reply=0x%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    AJ_SHA256_Init(&handshakeContext.hash);

    /*
     * Receive suites
     */
    status = AJ_UnmarshalArgs(msg, "au", &suites, &numsuites);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=0x%p, reply=0x%p): Unmarshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    numsuites /= sizeof (uint32_t);
    /*
     * Calculate common suites
     */
    common = (uint32_t*) AJ_Malloc(AUTH_SUITE_MAX * sizeof (uint32_t));
    if (!common) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=0x%p, reply=0x%p): AJ_ERR_RESOURCES\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    numcommon = 0;
    for (i = 0; i < msg->bus->numsuites; i++) {
        for (j = 0; j < numsuites; j++) {
            if (msg->bus->suites[i] == suites[j]) {
                common[numcommon++] = suites[j];
            }
        }
    }
    if (!numcommon) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=0x%p, reply=0x%p): No common suites\n", msg, reply));
        AJ_Free(common);
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    /*
     * Send common suites
     */
    AJ_MarshalReplyMsg(msg, reply);
    status = AJ_MarshalArgs(reply, "au", common, numcommon * sizeof (uint32_t));
    AJ_Free(common);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=0x%p, reply=0x%p): Marshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    return status;
}

AJ_Status AJ_PeerHandleExchangeSuitesReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t* suites;
    size_t numsuites;
    size_t i, j;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=0x%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=0x%p): error=%s.\n", msg, msg->error));
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else {
            status = AJ_ERR_SECURITY;
            HandshakeComplete(status);
        }
        return status;
    }

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * Receive common suites
     */
    status = AJ_UnmarshalArgs(msg, "au", &suites, &numsuites);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=0x%p): Unmarshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    numsuites /= sizeof (uint32_t);

    /*
     * Double check we can support (ie. that server didn't send something bogus)
     */
    handshakeContext.numsuites = 0;
    for (i = 0; i < msg->bus->numsuites; i++) {
        for (j = 0; j < numsuites; j++) {
            if (msg->bus->suites[i] == suites[j]) {
                handshakeContext.numsuites++;
            }
        }
    }

    if ((0 == handshakeContext.numsuites) || (numsuites != handshakeContext.numsuites)) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=0x%p): No common suites\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    handshakeContext.suites = (uint32_t*) AJ_Malloc(handshakeContext.numsuites * sizeof (uint32_t));
    if (!handshakeContext.suites) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=0x%p): AJ_ERR_RESOURCES\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_RESOURCES;
    }
    handshakeContext.suite = 0;
    for (i = 0; i < msg->bus->numsuites; i++) {
        for (j = 0; j < numsuites; j++) {
            if (msg->bus->suites[i] == suites[j]) {
                handshakeContext.suites[handshakeContext.suite++] = suites[j];
            }
        }
    }

    /*
     * Exchange suites complete.
     * Try each suite in order of preference.
     */
    AJ_InfoPrintf(("Exchange Suites Complete\n"));
    handshakeContext.suite = 0;
    status = KeyExchange(msg);
    if (status != AJ_OK) {
        HandshakeComplete(status);
    }
    return status;
}

static AJ_Status KeyExchange(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t suite;
    uint8_t suiteb8[sizeof (uint32_t)];
    AJ_Message call;

    AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p)\n", msg));

    if (handshakeContext.suite >= handshakeContext.numsuites) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): No remaining suites\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    suite = handshakeContext.suites[handshakeContext.suite++];
    AJ_InfoPrintf(("Authenticating using suite %x\n", suite));
    status = SetCipherSuite(msg->bus, suite);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): Suite 0x%x not available\n", msg, suite));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    if (!handshakeContext.keyexchange) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): Invalid key exchange\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    /*
     * Initialise the key exchange mechanism
     */
    status = handshakeContext.keyexchange->Init(&handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): Key exchange init error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    AJ_SHA256_Init(&handshakeContext.hash);
    /*
     * Send suite and key material
     */
    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_KEY_EXCHANGE, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    status = AJ_MarshalArgs(&call, "u", suite);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): Marshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    U32ToU8(&suite, sizeof (suite), suiteb8);
    AJ_SHA256_Update(&handshakeContext.hash, suiteb8, sizeof (suiteb8));
    status = handshakeContext.keyexchange->Marshal(&call);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_KeyExchange(msg=0x%p): Key exchange marshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    return AJ_DeliverMsg(&call);
}

AJ_Status AJ_PeerHandleKeyExchange(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    uint32_t suite;
    uint8_t suiteb8[sizeof (uint32_t)];
    uint8_t* secret;
    size_t secretlen;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    /*
     * Receive suite
     */
    AJ_UnmarshalArgs(msg, "u", &suite);
    status = SetCipherSuite(msg->bus, suite);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p): Marshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    U32ToU8(&suite, sizeof (suite), suiteb8);
    AJ_SHA256_Update(&handshakeContext.hash, suiteb8, sizeof (suiteb8));

    if (!handshakeContext.keyexchange) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p): Invalid key exchange\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    /*
     * Initialise the key exchange mechanism
     */
    status = handshakeContext.keyexchange->Init(&handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p): Key exchange init error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    /*
     * Receive key material
     */
    status = handshakeContext.keyexchange->Unmarshal(msg, &secret, &secretlen);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p): Key exchange unmarshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = ComputeMasterSecret(secret, secretlen);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p): Compute master secret error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    /*
     * Send key material
     */
    AJ_MarshalReplyMsg(msg, reply);
    status = AJ_MarshalArgs(reply, "u", suite);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p): Marshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    AJ_SHA256_Update(&handshakeContext.hash, (uint8_t*) suiteb8, sizeof (suiteb8));
    status = handshakeContext.keyexchange->Marshal(reply);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=0x%p, reply=0x%p): Key exchange marshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    handshakeContext.state = AJ_AUTH_EXCHANGED;
    AJ_InfoPrintf(("Key Exchange Complete\n"));
    return status;
}

AJ_Status AJ_PeerHandleKeyExchangeReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t suite;
    uint8_t suiteb8[sizeof (uint32_t)];
    uint8_t* secret;
    size_t secretlen;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleKeyExchangeReply(msg=0x%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyExchangeReply(msg=0x%p): error=%s.\n", msg, msg->error));
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else {
            status = AJ_ERR_SECURITY;
            HandshakeComplete(status);
        }
        return status;
    }

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    if (!handshakeContext.keyexchange) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyExchangeReply(msg=0x%p): Invalid key exchange\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    /*
     * Receive key material
     */
    status = AJ_UnmarshalArgs(msg, "u", &suite);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyExchangeReply(msg=0x%p): Unmarshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    U32ToU8(&suite, sizeof (suite), suiteb8);
    AJ_SHA256_Update(&handshakeContext.hash, suiteb8, sizeof (suiteb8));
    status = handshakeContext.keyexchange->Unmarshal(msg, &secret, &secretlen);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyExchangeReply(msg=0x%p): Key exchange unmarshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    status = ComputeMasterSecret(secret, secretlen);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyExchangeReply(msg=0x%p): Compute master secret error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    /*
     * Key exchange complete - start the authentication
     */
    handshakeContext.state = AJ_AUTH_EXCHANGED;
    AJ_InfoPrintf(("Key Exchange Complete\n"));
    status = KeyAuthentication(msg);
    if (status != AJ_OK) {
        HandshakeComplete(status);
    }
    return status;
}

static AJ_Status KeyAuthentication(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message call;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_KeyAuthentication(msg=0x%p)\n", msg));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    if (AJ_AUTH_EXCHANGED != handshakeContext.state) {
        AJ_InfoPrintf(("AJ_KeyAuthentication(msg=0x%p): Invalid state\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    if (!handshakeContext.keyauthentication) {
        AJ_InfoPrintf(("AJ_KeyAuthentication(msg=0x%p): Invalid key authentication\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    status = handshakeContext.keyauthentication->Init(msg->bus->authListenerCallback, handshakeContext.mastersecret, AJ_MASTER_SECRET_LEN, &handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_KeyAuthentication(msg=0x%p): Key authentication init error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    /*
     * Send authentication material
     */
    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_KEY_AUTHENTICATION, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    status = handshakeContext.keyauthentication->Marshal(&call, AUTH_CLIENT);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_KeyAuthentication(msg=0x%p): Key authentication marshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    return AJ_DeliverMsg(&call);
}

AJ_Status AJ_PeerHandleKeyAuthentication(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    uint32_t expiration;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=0x%p, reply=0x%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    if (AJ_AUTH_EXCHANGED != handshakeContext.state) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=0x%p, reply=0x%p): Invalid state\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    if (!handshakeContext.keyauthentication) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=0x%p, reply=0x%p): Invalid key authentication\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    status = handshakeContext.keyauthentication->Init(msg->bus->authListenerCallback, handshakeContext.mastersecret, AJ_MASTER_SECRET_LEN, &handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=0x%p, reply=0x%p): Key authentication init error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    /*
     * Receive authentication material
     */
    status = handshakeContext.keyauthentication->Unmarshal(msg, AUTH_SERVER);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=0x%p, reply=0x%p): Key authentication unmarshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    /*
     * Send authentication material
     */
    AJ_MarshalReplyMsg(msg, reply);
    status = handshakeContext.keyauthentication->Marshal(reply, AUTH_SERVER);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=0x%p, reply=0x%p): Key authentication marshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    AJ_InfoPrintf(("Key Authentication Complete\n"));
    handshakeContext.state = AJ_AUTH_SUCCESS;
    handshakeContext.keyauthentication->Final(&expiration);

    status = SaveMasterSecret(peerGuid, expiration);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=0x%p, reply=0x%p): Save master secret error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }

    return status;
}

AJ_Status AJ_PeerHandleKeyAuthenticationReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t expiration;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=0x%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=0x%p): error=%s.\n", msg, msg->error));
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else {
            status = AJ_ERR_SECURITY;
            HandshakeComplete(status);
        }
        return status;
    }

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    if (AJ_AUTH_EXCHANGED != handshakeContext.state) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=0x%p): Invalid state\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    if (!handshakeContext.keyauthentication) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=0x%p): Invalid key authentication\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
    /*
     * Receive authentication material
     */
    status = handshakeContext.keyauthentication->Unmarshal(msg, AUTH_CLIENT);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=0x%p): Key authentication unmarshal error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    /*
     * Key authentication complete - start the session
     */
    AJ_InfoPrintf(("Key Authentication Complete\n"));
    handshakeContext.state = AJ_AUTH_SUCCESS;
    handshakeContext.keyauthentication->Final(&expiration);

    peerGuid = AJ_GUID_Find(msg->sender);
    status = SaveMasterSecret(peerGuid, expiration);
    if (AJ_OK != status) {
        AJ_ErrPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=0x%p): Save master secret error\n", msg));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }

    status = GenSessionKey(msg);
    if (status != AJ_OK) {
        HandshakeComplete(status);
    }
    return status;
}

#ifndef NO_AUTH_PIN_KEYX
static AJ_Status GenSessionKey(AJ_Message* msg)
{
    AJ_Message call;
    char guidStr[33];
    AJ_GUID localGuid;

    AJ_InfoPrintf(("GenSessionKey(msg=0x%p)\n", msg));

    if (AJ_AUTH_SUCCESS != handshakeContext.state) {
        return AJ_ERR_SECURITY;
    }
    memset(&sessionContext, 0, sizeof(SessionContext));

    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_GEN_SESSION_KEY, msg->sender, 0, AJ_NO_FLAGS, AJ_CALL_TIMEOUT);
    /*
     * Marshal local peer GUID, remote peer GUID, and local peer's GUID
     */
    AJ_GetLocalGUID(&localGuid);
    AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    AJ_MarshalArgs(&call, "s", guidStr);
    AJ_GUID_ToString(authContext.peerGuid, guidStr, sizeof(guidStr));
    AJ_RandHex(sessionContext.nonce, sizeof(sessionContext.nonce), AJ_NONCE_LEN);
    AJ_MarshalArgs(&call, "ss", guidStr, sessionContext.nonce);

    return AJ_DeliverMsg(&call);
}
#endif

AJ_Status AJ_PeerHandleGenSessionKey(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    char* remGuid;
    char* locGuid;
    char* nonce;
    AJ_GUID guid;
    AJ_GUID localGuid;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    /*
     * For 12 bytes of verifier, we need at least 12 * 2 characters
     * to store its representation in hex (24 octets + 1 octet for \0).
     * However, the KeyGen function demands a bigger buffer
     * (to store 16 bytes key in addition to the 12 bytes verifier).
     * Hence we allocate, the maximum of (12 * 2 + 1) and (16 + 12).
     */
    char verifier[AES_KEY_LEN + AJ_VERIFIER_LEN];

    AJ_InfoPrintf(("AJ_PeerHandleGenSessionKey(msg=0x%p, reply=0x%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    /*
     * Remote peer GUID, Local peer GUID and Remote peer's nonce
     */
    AJ_UnmarshalArgs(msg, "sss", &remGuid, &locGuid, &nonce);
    /*
     * We expect arg[1] to be the local GUID
     */
    status = AJ_GUID_FromString(&guid, locGuid);
    if (AJ_OK == status) {
        status = AJ_GetLocalGUID(&localGuid);
    }
    if ((status != AJ_OK) || (memcmp(&guid, &localGuid, sizeof(AJ_GUID)) != 0)) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    AJ_RandHex(sessionContext.nonce, sizeof(sessionContext.nonce), AJ_NONCE_LEN);
    status = KeyGen(msg->sender, AJ_ROLE_KEY_RESPONDER, nonce, sessionContext.nonce, (uint8_t*)verifier, sizeof(verifier));
    if (status == AJ_OK) {
        AJ_MarshalReplyMsg(msg, reply);
        status = AJ_MarshalArgs(reply, "ss", sessionContext.nonce, verifier);
    } else {
        status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    return status;
}

AJ_Status AJ_PeerHandleGenSessionKeyReply(AJ_Message* msg)
{
    AJ_Status status;
    /*
     * For 12 bytes of verifier, we need at least 12 * 2 characters
     * to store its representation in hex (24 octets + 1 octet for \0).
     * However, the KeyGen function demands a bigger buffer
     * (to store 16 bytes key in addition to the 12 bytes verifier).
     * Hence we allocate, the maximum of (12 * 2 + 1) and (16 + 12).
     */
    char verifier[AJ_VERIFIER_LEN + AES_KEY_LEN];
    char* nonce;
    char* remVerifier;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleGetSessionKeyReply(msg=0x%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_ErrPrintf(("AJ_PeerHandleGetSessionKeyReply(msg=0x%p): error=%s.\n", msg, msg->error));
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else {
            status = AJ_ERR_SECURITY;
            HandshakeComplete(status);
        }
        return status;
    }

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    AJ_UnmarshalArgs(msg, "ss", &nonce, &remVerifier);
    status = KeyGen(msg->sender, AJ_ROLE_KEY_INITIATOR, sessionContext.nonce, nonce, (uint8_t*)verifier, sizeof(verifier));
    if (status == AJ_OK) {
        /*
         * Check verifier strings match as expected
         */
        if (strcmp(remVerifier, verifier) != 0) {
            AJ_ErrPrintf(("AJ_PeerHandleGetSessionKeyReply(): AJ_ERR_SECURITY\n"));
            status = AJ_ERR_SECURITY;
        }
    }
    if (status == AJ_OK) {
        AJ_Arg key;
        AJ_Message call;
        uint8_t groupKey[AES_KEY_LEN];
        /*
         * Group keys are exchanged via an encrypted message
         */
        AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_EXCHANGE_GROUP_KEYS, msg->sender, 0, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
        AJ_GetGroupKey(NULL, groupKey);
        AJ_MarshalArg(&call, AJ_InitArg(&key, AJ_ARG_BYTE, AJ_ARRAY_FLAG, groupKey, sizeof(groupKey)));
        status = AJ_DeliverMsg(&call);
    }
    if (status != AJ_OK) {
        HandshakeComplete(status);
    }
    return AJ_OK;
}

AJ_Status AJ_PeerHandleExchangeGroupKeys(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Arg key;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGroupKeys(msg=0x%p, reply=0x%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    AJ_UnmarshalArg(msg, &key);
    /*
     * We expect the key to be 16 bytes
     */
    if (key.len != AES_KEY_LEN) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGroupKeys(): AJ_ERR_INVALID\n"));
        status = AJ_ERR_INVALID;
    } else {
        status = AJ_SetGroupKey(msg->sender, key.val.v_byte);
    }
    if (status == AJ_OK) {
        uint8_t groupKey[AES_KEY_LEN];
        AJ_MarshalReplyMsg(msg, reply);
        AJ_GetGroupKey(NULL, groupKey);
        status = AJ_MarshalArg(reply, AJ_InitArg(&key, AJ_ARG_BYTE, AJ_ARRAY_FLAG, groupKey, sizeof(groupKey)));
    } else {
        status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    HandshakeComplete(status);
    return status;
}

AJ_Status AJ_PeerHandleExchangeGroupKeysReply(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg arg;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGroupKeysReply(msg=0x%p)\n", msg));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    AJ_UnmarshalArg(msg, &arg);
    /*
     * We expect the key to be 16 bytes
     */
    if (arg.len != AES_KEY_LEN) {
        AJ_ErrPrintf(("AJ_PeerHandleExchangeGroupKeysReply(msg=0x%p): AJ_ERR_INVALID\n", msg));
        status = AJ_ERR_INVALID;
    } else {
        status = AJ_SetGroupKey(msg->sender, arg.val.v_byte);
    }
    HandshakeComplete(status);
    return status;
}
