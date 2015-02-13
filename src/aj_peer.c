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
#define AJ_MODULE PEER

#include "aj_target.h"
#include "aj_peer.h"
#include "aj_bus.h"
#include "aj_msg.h"
#include "aj_util.h"
#include "aj_guid.h"
#include "aj_creds.h"
#include "aj_std.h"
#include "aj_crypto.h"
#include "aj_crypto_sha2.h"
#include "aj_debug.h"
#include "aj_config.h"
#include "aj_keyexchange.h"
#include "aj_keyauthentication.h"
#include "aj_cert.h"
#include "aj_x509.h"

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
#define MIN_AUTH_VERSION  0x0002
#define MAX_AUTH_VERSION  0x0003

#define REQUIRED_AUTH_VERSION  (((uint32_t)MAX_AUTH_VERSION << 16) | MIN_KEYGEN_VERSION)

#define EXCHANGE_KEYINFO 1
#define EXCHANGE_ANCHORS 2
#define SEND_CERT        1
#define SEND_CERT_CHAIN  2
#define SEND_AUTH_DATA   3

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
static AJ_Status SendMemberships(AJ_Message* msg);

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
    uint32_t suite;
} HandshakeContext;

typedef struct _SessionContext {
    char nonce[2 * AJ_NONCE_LEN + 1];  /* Nonce as ascii hex */
    uint8_t type;                      /* Current membership send type (CERT, AUTH_DATA) */
    uint16_t slot;                     /* Current nvram slot for membership certificate */
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

static uint32_t GetAcceptableVersion(uint32_t srcV)
{
    uint16_t authV = srcV >> 16;
    uint16_t keyV = srcV & 0xFFFF;

    if ((authV < MIN_AUTH_VERSION) || (authV > MAX_AUTH_VERSION)) {
        return 0;
    }
    if (keyV > MAX_KEYGEN_VERSION) {
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
    const AJ_GUID* peerGuid = AJ_GUID_Find(peerName);

    AJ_InfoPrintf(("KeyGen(peerName=\"%s\", role=%d., nonce1=\"%s\", nonce2=\"%s\", outbuf=%p, len=%d.)\n",
                   peerName, role, nonce1, nonce2, outBuf, len));

    if (NULL == peerGuid) {
        AJ_ErrPrintf(("KeyGen(): AJ_ERR_UNEXPECTED\n"));
        return AJ_ERR_UNEXPECTED;
    }

    data[0] = handshakeContext.mastersecret;
    lens[0] = (uint32_t)AJ_MASTER_SECRET_LEN;
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
    if (len < (AJ_SESSION_KEY_LEN + AJ_VERIFIER_LEN)) {
        AJ_WarnPrintf(("KeyGen(): AJ_ERR_RESOURCES\n"));
        return AJ_ERR_RESOURCES;
    }

    status = versionContext.PRF(data, lens, ArraySize(data), outBuf, AJ_SESSION_KEY_LEN + AJ_VERIFIER_LEN);
    /*
     * Store the session key and compose the verifier string.
     */
    if (status == AJ_OK) {
        status = AJ_SetSessionKey(peerName, outBuf, role);
    }
    if (status == AJ_OK) {
        memmove(outBuf, outBuf + AJ_SESSION_KEY_LEN, AJ_VERIFIER_LEN);
        status = AJ_RawToHex(outBuf, AJ_VERIFIER_LEN, (char*) outBuf, len, FALSE);
    }
    AJ_InfoPrintf(("KeyGen Verifier = %s.\n", outBuf));
    return status;
}

void AJ_ClearAuthContext()
{
    memset(&authContext, 0, sizeof(AuthContext));
    memset(&handshakeContext, 0, sizeof(HandshakeContext));
}

static void HandshakeComplete(AJ_Status status)
{

    uint32_t expiration;
    AJ_InfoPrintf(("HandshakeComplete(status=%d.)\n", status));

    if (authContext.callback) {
        authContext.callback(authContext.cbContext, status);
    }

    if ((AJ_OK != status) && (AJ_AUTH_EXCHANGED == handshakeContext.state)) {
        handshakeContext.keyauthentication->Final(&expiration);
    }
    AJ_ClearAuthContext();
}

static AJ_Status ComputeMasterSecret(uint8_t* secret, size_t secretlen)
{
    AJ_Status status;
    const uint8_t* data[2];
    uint8_t lens[2];

    AJ_InfoPrintf(("ComputeMasterSecret(secret=%p)\n", secret));

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

    AJ_InfoPrintf(("SaveMasterSecret(peerGuid=%p, expiration=%d)\n", peerGuid, expiration));

    if (peerGuid) {
        /*
         * If the authentication was succesful write the credentials for the authenticated peer to
         * NVRAM otherwise delete any stale credentials that might be stored.
         */
        if (AJ_AUTH_SUCCESS == handshakeContext.state) {
            status = AJ_StorePeerSecret(peerGuid, handshakeContext.mastersecret, AJ_MASTER_SECRET_LEN, expiration);
        } else {
            AJ_WarnPrintf(("SaveMasterSecret(peerGuid=%p, expiration=%d): Invalid state\n", peerGuid, expiration));
            status = AJ_DeletePeerCredential(peerGuid);
        }
    } else {
        status = AJ_ERR_SECURITY;
    }

    return status;
}

static AJ_Status HandshakeTimeout() {
    uint8_t zero[sizeof (AJ_GUID)];
    memset(zero, 0, sizeof (zero));
    /*
     * If handshake started, check peer is still around
     * If peer disappeared, AJ_GUID_DeleteNameMapping writes zeros
     */
    if (authContext.peerGuid) {
        if (!memcmp(authContext.peerGuid, zero, sizeof (zero))) {
            AJ_WarnPrintf(("AJ_HandshakeTimeout(): Peer disappeared\n"));
            authContext.peerGuid = NULL;
            HandshakeComplete(AJ_ERR_TIMEOUT);
            return AJ_ERR_TIMEOUT;
        }
    }
    if (AJ_GetElapsedTime(&authContext.timer, TRUE) >= AJ_MAX_AUTH_TIME) {
        AJ_WarnPrintf(("AJ_HandshakeTimeout(): AJ_ERR_TIMEOUT\n"));
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
        AJ_InfoPrintf(("AJ_HandshakeValid(peerGuid=%p): Invalid peer guid\n", peerGuid));
        return AJ_ERR_SECURITY;
    }
    /*
     * Handshake timed out
     */
    if (AJ_OK != HandshakeTimeout()) {
        AJ_InfoPrintf(("AJ_HandshakeValid(peerGuid=%p): Handshake timed out\n", peerGuid));
        return AJ_ERR_TIMEOUT;
    }
    /*
     * Handshake call from different peer
     */
    if (!peerGuid || (peerGuid != authContext.peerGuid)) {
        AJ_WarnPrintf(("AJ_HandshakeValid(peerGuid=%p): Invalid peer guid\n", peerGuid));
        return AJ_ERR_RESOURCES;
    }

    return AJ_OK;
}

AJ_Status AJ_PeerAuthenticate(AJ_BusAttachment* bus, const char* peerName, AJ_PeerAuthenticateCallback callback, void* cbContext)
{
#ifndef NO_SECURITY
    AJ_Status status;
    AJ_Message msg;
    char guidStr[2 * AJ_GUID_LEN + 1];
    AJ_GUID localGuid;
    uint32_t version = REQUIRED_AUTH_VERSION;

    AJ_InfoPrintf(("PeerAuthenticate(bus=%p, peerName=\"%s\", callback=%p, cbContext=%p)\n",
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
    AJ_ClearAuthContext();
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
    AJ_Cred cred;

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p)\n", msg, reply));

    /*
     * If handshake in progress and not timed-out
     */
    if (authContext.peerGuid) {
        status = HandshakeTimeout();
        if (AJ_ERR_TIMEOUT != status) {
            AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Handshake in progress\n", msg, reply));
            return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
        }
    }

    /*
     * No handshake in progress or previous timed-out
     */
    AJ_ClearAuthContext();
    AJ_InitTimer(&authContext.timer);

    status = AJ_UnmarshalArgs(msg, "su", &str, &version);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Unmarshal error\n", msg, reply));
        goto ExitFail;
    }
    status = AJ_GUID_FromString(&remoteGuid, str);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Invalid GUID\n", msg, reply));
        goto ExitFail;
    }
    status = AJ_GUID_AddNameMapping(msg->bus, &remoteGuid, msg->sender, NULL);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Add name mapping error\n", msg, reply));
        goto ExitFail;
    }
    authContext.peerGuid = AJ_GUID_Find(msg->sender);

    /*
     * If we have a mastersecret stored - use it
     */
    status = AJ_GetPeerCredential(authContext.peerGuid, &cred);
    if (AJ_OK == status) {
        status = AJ_CredentialExpired(&cred);
        if (AJ_ERR_KEY_EXPIRED != status) {
            /* secret not expired or time unknown */
            handshakeContext.state = AJ_AUTH_SUCCESS;
            AJ_ASSERT(AJ_MASTER_SECRET_LEN == cred.body.data.size);
            memcpy(handshakeContext.mastersecret, cred.body.data.data, cred.body.data.size);
        } else {
            AJ_DeletePeerCredential(authContext.peerGuid);
        }
        AJ_CredBodyFree(&cred.body);
    }

    /*
     * We are not currently negotiating versions so we tell the peer what version we require.
     */
    version = GetAcceptableVersion(version);
    if (0 == version) {
        version = REQUIRED_AUTH_VERSION;
    }
    AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Version %x\n", msg, reply, version));
    status = SetAuthVersion(version);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Invalid version\n", msg, reply));
        goto ExitFail;
    }

    AJ_MarshalReplyMsg(msg, reply);
    AJ_GetLocalGUID(&localGuid);
    AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    return AJ_MarshalArgs(reply, "su", guidStr, version);

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_PeerHandleExchangeGUIDsReply(AJ_Message* msg)
{
    AJ_Status status;
    const char* guidStr;
    AJ_GUID remoteGuid;
    uint32_t version;
    AJ_Cred cred;

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): error=%s.\n", msg, msg->error));
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
            AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Handshake in progress\n", msg));
            return AJ_ERR_RESOURCES;
        }
    }

    status = AJ_UnmarshalArgs(msg, "su", &guidStr, &version);
    if (status != AJ_OK) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Unmarshal error\n", msg));
        goto ExitFail;
    }
    version = GetAcceptableVersion(version);
    if (0 == version) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Invalid version\n", msg));
        goto ExitFail;
    }
    status = SetAuthVersion(version);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Invalid version\n", msg));
        goto ExitFail;
    }
    status = AJ_GUID_FromString(&remoteGuid, guidStr);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Invalid GUID\n", msg));
        goto ExitFail;
    }
    /*
     * Two name mappings to add, the well known name, and the unique name from the message.
     */
    status = AJ_GUID_AddNameMapping(msg->bus, &remoteGuid, msg->sender, authContext.peerName);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Add name mapping error\n", msg));
        goto ExitFail;
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
        status = AJ_CredentialExpired(&cred);
        if (AJ_ERR_KEY_EXPIRED != status) {
            /* secret not expired or time unknown */
            handshakeContext.state = AJ_AUTH_SUCCESS;
            /* assert that MASTER_SECRET_LEN == cred.body.data.size */
            memcpy(handshakeContext.mastersecret, cred.body.data.data, cred.body.data.size);
            AJ_CredBodyFree(&cred.body);
            status = GenSessionKey(msg);
            return status;
        } else {
            AJ_DeletePeerCredential(authContext.peerGuid);
        }
        AJ_CredBodyFree(&cred.body);
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

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

static AJ_Status ExchangeSuites(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message call;
    uint32_t suites[AJ_AUTH_SUITES_NUM];
    size_t num = 0;

    AJ_InfoPrintf(("ExchangeSuites(msg=%p)\n", msg));

    AJ_SHA256_Init(&handshakeContext.hash);

    /*
     * Send suites
     */
    if (AJ_IsSuiteEnabled(msg->bus, AUTH_SUITE_ECDHE_NULL)) {
        suites[num++] = AUTH_SUITE_ECDHE_NULL;
    }
    if (AJ_IsSuiteEnabled(msg->bus, AUTH_SUITE_ECDHE_PSK)) {
        suites[num++] = AUTH_SUITE_ECDHE_PSK;
    }
    if (AJ_IsSuiteEnabled(msg->bus, AUTH_SUITE_ECDHE_ECDSA)) {
        suites[num++] = AUTH_SUITE_ECDHE_ECDSA;
    }
    if (!num) {
        AJ_WarnPrintf(("ExchangeSuites(msg=%p): No suites available\n", msg));
        goto ExitFail;
    }
    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_EXCHANGE_SUITES, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    status = AJ_MarshalArgs(&call, "au", suites, num * sizeof (uint32_t));
    if (AJ_OK != status) {
        AJ_WarnPrintf(("ExchangeSuites(msg=%p): Marshal error\n", msg));
        goto ExitFail;
    }

    return AJ_DeliverMsg(&call);

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

AJ_Status AJ_PeerHandleExchangeSuites(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Arg array;
    uint32_t* suites;
    size_t numsuites;
    uint32_t i;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=%p, reply=%p)\n", msg, reply));

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
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=%p, reply=%p): Unmarshal error\n", msg, reply));
        goto ExitFail;
    }
    numsuites /= sizeof (uint32_t);

    /*
     * Calculate common suites
     */
    AJ_MarshalReplyMsg(msg, reply);
    status = AJ_MarshalContainer(reply, &array, AJ_ARG_ARRAY);
    /* Iterate through the available suites.
     * If it's enabled, marshal the suite to send to the other peer.
     */
    for (i = 0; i < numsuites; i++) {
        if (AJ_IsSuiteEnabled(msg->bus, suites[i])) {
            status = AJ_MarshalArgs(reply, "u", suites[i]);
        }
    }
    status = AJ_MarshalCloseContainer(reply, &array);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeSuites(msg=%p, reply=%p): Marshal error\n", msg, reply));
        goto ExitFail;
    }

    AJ_InfoPrintf(("Exchange Suites Complete\n"));
    return status;

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_PeerHandleExchangeSuitesReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t* suites;
    size_t numsuites;
    size_t i;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=%p): error=%s.\n", msg, msg->error));
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
     * Receive suites
     */
    status = AJ_UnmarshalArgs(msg, "au", &suites, &numsuites);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=%p): Unmarshal error\n", msg));
        goto ExitFail;
    }
    numsuites /= sizeof (uint32_t);

    /*
     * Double check we can support (ie. that server didn't send something bogus)
     */
    handshakeContext.suite = 0;
    for (i = 0; i < numsuites; i++) {
        if (AJ_IsSuiteEnabled(msg->bus, suites[i])) {
            handshakeContext.suite = suites[i];
        }
    }
    if (!handshakeContext.suite) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=%p): No common suites\n", msg));
        goto ExitFail;
    }

    /*
     * Exchange suites complete.
     */
    AJ_InfoPrintf(("Exchange Suites Complete\n"));
    status = KeyExchange(msg);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    return status;

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

static AJ_Status KeyExchange(AJ_Message* msg)
{
    AJ_Status status;
    uint8_t suiteb8[sizeof (uint32_t)];
    AJ_Message call;
    AJ_Arg container1;
    AJ_Arg container2;

    AJ_InfoPrintf(("KeyExchange(msg=%p)\n", msg));

    if (!handshakeContext.suite) {
        AJ_WarnPrintf(("KeyExchange(msg=%p): No remaining suites\n", msg));
        goto ExitFail;
    }
    AJ_InfoPrintf(("Authenticating using suite %x\n", handshakeContext.suite));
    status = SetCipherSuite(msg->bus, handshakeContext.suite);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("KeyExchange(msg=%p): Suite 0x%x not available\n", msg, handshakeContext.suite));
        goto ExitFail;
    }

    if (!handshakeContext.keyexchange) {
        AJ_WarnPrintf(("KeyExchange(msg=%p): Invalid key exchange\n", msg));
        goto ExitFail;
    }
    /*
     * Initialise the key exchange mechanism
     */
    status = handshakeContext.keyexchange->Init(&handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("KeyExchange(msg=%p): Key exchange init error\n", msg));
        goto ExitFail;
    }

    AJ_SHA256_Init(&handshakeContext.hash);
    /*
     * Send suite and key material
     */
    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_KEY_EXCHANGE, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    status = AJ_MarshalArgs(&call, "u", handshakeContext.suite);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("KeyExchange(msg=%p): Marshal error\n", msg));
        goto ExitFail;
    }

    HostU32ToBigEndianU8(&handshakeContext.suite, sizeof (handshakeContext.suite), suiteb8);
    AJ_SHA256_Update(&handshakeContext.hash, suiteb8, sizeof (suiteb8));

    status = AJ_MarshalVariant(&call, "a(yv)");
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalContainer(&call, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalContainer(&call, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalArgs(&call, "y", EXCHANGE_KEYINFO);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = handshakeContext.keyexchange->Marshal(&call);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalCloseContainer(&call, &container2);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalContainer(&call, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalArgs(&call, "y", EXCHANGE_ANCHORS);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    /*
     * Future Improvement (TODO):
     * Exchange anchors and psk_hint, based on available suites.
     * This will prompt automatic authentication.. NULL -> ECDSA/PSK
     */
    status = AJ_TrustAnchorsMarshal(&call, 1, &handshakeContext.hash);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalCloseContainer(&call, &container2);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalCloseContainer(&call, &container1);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return AJ_DeliverMsg(&call);

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

AJ_Status AJ_PeerHandleKeyExchange(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t suiteb8[sizeof (uint32_t)];
    uint8_t* secret;
    size_t secretlen;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    char* variant;
    uint8_t tmp;
    uint8_t found;
    AJ_GUID ta;

    AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    /*
     * Receive suite
     */
    AJ_UnmarshalArgs(msg, "u", &handshakeContext.suite);
    status = SetCipherSuite(msg->bus, handshakeContext.suite);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p): Suite 0x%x not available\n", msg, reply, handshakeContext.suite));
        goto ExitFail;
    }
    HostU32ToBigEndianU8(&handshakeContext.suite, sizeof (handshakeContext.suite), suiteb8);
    AJ_SHA256_Update(&handshakeContext.hash, suiteb8, sizeof (suiteb8));

    if (!handshakeContext.keyexchange) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p): Invalid key exchange\n", msg, reply));
        goto ExitFail;
    }
    /*
     * Initialise the key exchange mechanism
     */
    status = handshakeContext.keyexchange->Init(&handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p): Key exchange init error\n", msg, reply));
        goto ExitFail;
    }

    /*
     * Receive key material and trust anchors
     */
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    if (0 != strncmp(variant, "a(yv)", 5)) {
        goto ExitFail;
    }
    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_UnmarshalArgs(msg, "y", &tmp);
        if (AJ_OK != status) {
            goto ExitFail;
        }
        switch (tmp) {
        case EXCHANGE_KEYINFO:
            status = handshakeContext.keyexchange->Unmarshal(msg);
            break;

        case EXCHANGE_ANCHORS:
            status = AJ_TrustAnchorsUnmarshal(msg, &found, &ta, &handshakeContext.hash);
            break;

        default:
            status = AJ_ERR_INVALID;
            break;
        }
        if (AJ_OK != status) {
            goto ExitFail;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            goto ExitFail;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    handshakeContext.keyexchange->GetSecret(&secret, &secretlen);
    status = ComputeMasterSecret(secret, secretlen);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p): Compute master secret error\n", msg, reply));
        goto ExitFail;
    }

    /*
     * Send key material and trust anchors
     */
    AJ_MarshalReplyMsg(msg, reply);
    status = AJ_MarshalArgs(reply, "u", handshakeContext.suite);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p): Marshal error\n", msg, reply));
        goto ExitFail;
    }
    AJ_SHA256_Update(&handshakeContext.hash, (uint8_t*) suiteb8, sizeof (suiteb8));

    status = AJ_MarshalVariant(reply, "a(yv)");
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalContainer(reply, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalContainer(reply, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalArgs(reply, "y", EXCHANGE_KEYINFO);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = handshakeContext.keyexchange->Marshal(reply);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalCloseContainer(reply, &container2);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalContainer(reply, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalArgs(reply, "y", EXCHANGE_ANCHORS);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_TrustAnchorsMarshal(reply, found, &handshakeContext.hash);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalCloseContainer(reply, &container2);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_MarshalCloseContainer(reply, &container1);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    handshakeContext.state = AJ_AUTH_EXCHANGED;
    AJ_InfoPrintf(("Key Exchange Complete\n"));

    return status;

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_PeerHandleKeyExchangeReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t suite;
    uint8_t suiteb8[sizeof (uint32_t)];
    uint8_t* secret;
    size_t secretlen;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    char* variant;
    AJ_Arg container1;
    AJ_Arg container2;
    uint8_t tmp;
    AJ_GUID ta;
    uint8_t found;

    AJ_InfoPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): error=%s.\n", msg, msg->error));
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
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): Invalid key exchange\n", msg));
        goto ExitFail;
    }
    /*
     * Receive key material
     */
    status = AJ_UnmarshalArgs(msg, "u", &suite);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): Unmarshal error\n", msg));
        goto ExitFail;
    }
    if (suite != handshakeContext.suite) {
        goto ExitFail;
    }
    HostU32ToBigEndianU8(&suite, sizeof (suite), suiteb8);
    AJ_SHA256_Update(&handshakeContext.hash, suiteb8, sizeof (suiteb8));

    /*
     * Receive key material and trust anchors
     */
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    if (0 != strncmp(variant, "a(yv)", 5)) {
        goto ExitFail;
    }
    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_UnmarshalArgs(msg, "y", &tmp);
        if (AJ_OK != status) {
            goto ExitFail;
        }
        switch (tmp) {
        case EXCHANGE_KEYINFO:
            status = handshakeContext.keyexchange->Unmarshal(msg);
            break;

        case EXCHANGE_ANCHORS:
            status = AJ_TrustAnchorsUnmarshal(msg, &found, &ta, &handshakeContext.hash);
            break;

        default:
            status = AJ_ERR_INVALID;
            break;
        }
        if (AJ_OK != status) {
            goto ExitFail;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            goto ExitFail;
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    handshakeContext.keyexchange->GetSecret(&secret, &secretlen);
    status = ComputeMasterSecret(secret, secretlen);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): Compute master secret error\n", msg));
        goto ExitFail;
    }

    /*
     * Key exchange complete - start the authentication
     */
    handshakeContext.state = AJ_AUTH_EXCHANGED;
    AJ_InfoPrintf(("Key Exchange Complete\n"));
    status = KeyAuthentication(msg);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    return status;

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

static AJ_Status KeyAuthentication(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message call;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_KeyAuthentication(msg=%p)\n", msg));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    if (AJ_AUTH_EXCHANGED != handshakeContext.state) {
        AJ_WarnPrintf(("AJ_KeyAuthentication(msg=%p): Invalid state\n", msg));
        goto ExitFail;
    }
    if (!handshakeContext.keyauthentication) {
        AJ_WarnPrintf(("AJ_KeyAuthentication(msg=%p): Invalid key authentication\n", msg));
        goto ExitFail;
    }
    status = handshakeContext.keyauthentication->Init(msg->bus->authListenerCallback, handshakeContext.mastersecret, AJ_MASTER_SECRET_LEN, &handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_KeyAuthentication(msg=%p): Key authentication init error\n", msg));
        goto ExitFail;
    }

    /*
     * Send authentication material
     */
    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_KEY_AUTHENTICATION, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    status = handshakeContext.keyauthentication->Marshal(&call, AUTH_CLIENT);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_KeyAuthentication(msg=%p): Key authentication marshal error\n", msg));
        goto ExitFail;
    }

    return AJ_DeliverMsg(&call);

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

AJ_Status AJ_PeerHandleKeyAuthentication(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    uint32_t expiration;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    AJ_Identity identity;

    AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    if (AJ_AUTH_EXCHANGED != handshakeContext.state) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Invalid state\n", msg, reply));
        goto ExitFail;
    }
    if (!handshakeContext.keyauthentication) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Invalid key authentication\n", msg, reply));
        goto ExitFail;
    }

    status = handshakeContext.keyauthentication->Init(msg->bus->authListenerCallback, handshakeContext.mastersecret, AJ_MASTER_SECRET_LEN, &handshakeContext.hash);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Key authentication init error\n", msg, reply));
        goto ExitFail;
    }
    /*
     * Receive authentication material
     */
    status = handshakeContext.keyauthentication->Unmarshal(msg, AUTH_SERVER);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Key authentication unmarshal error\n", msg, reply));
        goto ExitFail;
    }

    /*
     * Send authentication material
     */
    AJ_MarshalReplyMsg(msg, reply);
    status = handshakeContext.keyauthentication->Marshal(reply, AUTH_SERVER);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Key authentication marshal error %s\n", msg, reply));
        goto ExitFail;
    }

    handshakeContext.state = AJ_AUTH_SUCCESS;
    handshakeContext.keyauthentication->GetIdentity(&identity, &expiration);
    if (expiration) {
        status = SaveMasterSecret(peerGuid, expiration);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Save master secret error\n", msg, reply));
        }
    }
    AJ_AuthRecordApply(&identity, msg->sender);
    handshakeContext.keyauthentication->Final();
    AJ_InfoPrintf(("Key Authentication Complete\n"));

    return status;

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_PeerHandleKeyAuthenticationReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t expiration;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    AJ_Identity identity;

    AJ_InfoPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): error=%s.\n", msg, msg->error));
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
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): Invalid state\n", msg));
        goto ExitFail;
    }
    if (!handshakeContext.keyauthentication) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): Invalid key authentication\n", msg));
        goto ExitFail;
    }
    /*
     * Receive authentication material
     */
    status = handshakeContext.keyauthentication->Unmarshal(msg, AUTH_CLIENT);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): Key authentication unmarshal error\n", msg));
        goto ExitFail;
    }

    /*
     * Key authentication complete - start the session
     */
    handshakeContext.state = AJ_AUTH_SUCCESS;
    handshakeContext.keyauthentication->GetIdentity(&identity, &expiration);
    if (expiration) {
        status = SaveMasterSecret(peerGuid, expiration);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): Save master secret error\n", msg));
        }
    }
    handshakeContext.keyauthentication->Final();
    AJ_InfoPrintf(("Key Authentication Complete\n"));

    status = GenSessionKey(msg);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    return status;

ExitFail:

    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

static AJ_Status GenSessionKey(AJ_Message* msg)
{
    AJ_Message call;
    char guidStr[33];
    AJ_GUID localGuid;

    AJ_InfoPrintf(("GenSessionKey(msg=%p)\n", msg));

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
    char verifier[AJ_SESSION_KEY_LEN + AJ_VERIFIER_LEN];

    AJ_InfoPrintf(("AJ_PeerHandleGenSessionKey(msg=%p, reply=%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }
    if (AJ_AUTH_SUCCESS != handshakeContext.state) {
        /*
         * We don't have a saved master secret and we haven't generated one yet
         */
        AJ_InfoPrintf(("AJ_PeerHandleGenSessionKey(msg=%p, reply=%p): Key not available\n", msg, reply));
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrRejected);
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
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    AJ_RandHex(sessionContext.nonce, sizeof(sessionContext.nonce), AJ_NONCE_LEN);
    status = KeyGen(msg->sender, AJ_ROLE_KEY_RESPONDER, nonce, sessionContext.nonce, (uint8_t*)verifier, sizeof(verifier));
    if (status == AJ_OK) {
        AJ_MarshalReplyMsg(msg, reply);
        status = AJ_MarshalArgs(reply, "ss", sessionContext.nonce, verifier);
    } else {
        HandshakeComplete(AJ_ERR_SECURITY);
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
    char verifier[AJ_VERIFIER_LEN + AJ_SESSION_KEY_LEN];
    char* nonce;
    char* remVerifier;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleGetSessionKeyReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleGetSessionKeyReply(msg=%p): error=%s.\n", msg, msg->error));
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else if (0 == strncmp(msg->error, AJ_ErrRejected, sizeof(AJ_ErrRejected))) {
            status = ExchangeSuites(msg);
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
            AJ_WarnPrintf(("AJ_PeerHandleGetSessionKeyReply(): AJ_ERR_SECURITY\n"));
            status = AJ_ERR_SECURITY;
        }
    }
    if (status == AJ_OK) {
        AJ_Arg key;
        AJ_Message call;
        uint8_t groupKey[AJ_SESSION_KEY_LEN];
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
    return status;
}

AJ_Status AJ_PeerHandleExchangeGroupKeys(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Arg key;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGroupKeys(msg=%p, reply=%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    AJ_UnmarshalArg(msg, &key);
    /*
     * We expect the key to be 16 bytes
     */
    if (key.len != AJ_SESSION_KEY_LEN) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGroupKeys(): AJ_ERR_INVALID\n"));
        status = AJ_ERR_INVALID;
    } else {
        status = AJ_SetGroupKey(msg->sender, key.val.v_byte);
    }
    if (status == AJ_OK) {
        uint8_t groupKey[AJ_SESSION_KEY_LEN];
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

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGroupKeysReply(msg=%p)\n", msg));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    AJ_UnmarshalArg(msg, &arg);
    /*
     * We expect the key to be 16 bytes
     */
    if (arg.len != AJ_SESSION_KEY_LEN) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGroupKeysReply(msg=%p): AJ_ERR_INVALID\n", msg));
        status = AJ_ERR_INVALID;
    } else {
        status = AJ_SetGroupKey(msg->sender, arg.val.v_byte);
    }
    HandshakeComplete(status);
    if (AJ_OK == status) {
        /*
         * Start by sending a membership certificate
         */
        sessionContext.slot = AJ_CREDS_NV_ID_BEGIN;
        sessionContext.type = SEND_CERT;
        SendMemberships(msg);
    }
    return status;
}

/*
 * For each membership, send the certificate in its own message.
 * If the membership also has authorisation data, send it in its own message.
 * This call is performed by both peers independently.
 */
static AJ_Status SendMemberships(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message call;
    AJ_CredHead head;
    AJ_CredBody body;
    AJ_Arg container1;
    AJ_Arg container2;
    AJ_Arg container3;

    AJ_InfoPrintf(("SendMemberships(msg=%p)\n", msg));

    switch (sessionContext.type) {
    case SEND_CERT:
        head.type = AJ_CERTIFICATE_MBR_X509_DER | AJ_CRED_TYPE_CERTIFICATE;
        head.id.data = NULL;
        head.id.size = 0;
        status = AJ_GetNextCredential(&head, &body, &sessionContext.slot);
        if (AJ_OK != status) {
            // No more left
            return status;
        }
        sessionContext.slot++;
        break;

    case SEND_CERT_CHAIN:
        // Currently not supported
        break;

    case SEND_AUTH_DATA:
        status = AJ_GetMembershipAuthData(sessionContext.slot, &body);
        if (AJ_OK != status) {
            // No authorisation data for this membership, try next certificate.
            sessionContext.type = SEND_CERT;
            SendMemberships(msg);
            return status;
        }
        break;
    }

    /*
     * If we got here, we have a message to send.
     * The message contents are in body.data
     */
    AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_SEND_MEMBERSHIPS, msg->sender, 0, AJ_FLAG_ENCRYPTED, AJ_AUTH_CALL_TIMEOUT);
    /*
     * The signature is an array but we only ever send one entry at a time (to keep message size down).
     */
    status = AJ_MarshalContainer(&call, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalContainer(&call, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto Exit;
    }
    // Index and total are not used in the thin client
    status = AJ_MarshalArgs(&call, "yy", 0, 0);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalVariant(&call, "(yv)");
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalContainer(&call, &container3, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalArgs(&call, "y", sessionContext.type);
    if (AJ_OK != status) {
        goto Exit;
    }
    switch (sessionContext.type) {
    case SEND_CERT:
        status = AJ_MarshalVariant(&call, "(ay)");
        if (AJ_OK != status) {
            goto Exit;
        }
        status = AJ_MarshalArgs(&call, "(ay)", body.data.data, body.data.size);
        if (AJ_OK != status) {
            goto Exit;
        }
        sessionContext.type = SEND_AUTH_DATA;
        break;

    case SEND_CERT_CHAIN:
        // Currently not supported
        break;

    case SEND_AUTH_DATA:
        status = AJ_MarshalVariant(&call, "ayay(yv)");
        if (AJ_OK != status) {
            goto Exit;
        }
        status = AJ_CredBodyMarshal(&body, &call);
        if (AJ_OK != status) {
            goto Exit;
        }
        sessionContext.type = SEND_CERT;
        break;
    }
    status = AJ_MarshalCloseContainer(&call, &container3);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalCloseContainer(&call, &container2);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalCloseContainer(&call, &container1);
    if (AJ_OK != status) {
        goto Exit;
    }

Exit:
    AJ_CredBodyFree(&body);

    if (AJ_OK == status) {
        status = AJ_DeliverMsg(&call);
    }

    return status;
}

AJ_Status AJ_PeerHandleSendMemberships(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    AJ_Arg container3;
    uint8_t index;
    uint8_t total;
    uint8_t type;
    char* variant;
    DER_Element der;
    X509Certificate certificate;
    AJ_KeyInfo pub;
    AJ_Identity identity;

    AJ_InfoPrintf(("AJ_PeerHandleSendMemberships(msg=%p, reply=%p)\n", msg, reply));

    /*
     * Receive memberships
     */
    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalArgs(msg, "yy", &index, &total);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    if (0 != strncmp(variant, "(yv)", 4)) {
        goto ExitFail;
    }
    status = AJ_UnmarshalContainer(msg, &container3, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalArgs(msg, "y", &type);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    switch (type) {
    case SEND_CERT:
        status = AJ_UnmarshalVariant(msg, (const char**) &variant);
        if (AJ_OK != status) {
            goto ExitFail;
        }
        if (0 != strncmp(variant, "(ay)", 4)) {
            goto ExitFail;
        }
        status = AJ_UnmarshalArgs(msg, "(ay)", &der.data, &der.size);
        if (AJ_OK != status) {
            goto ExitFail;
        }
        status = AJ_X509DecodeCertificateDER(&certificate, &der);
        if (AJ_OK != status) {
            goto ExitFail;
        }
        if (MEMBERSHIP_CERTIFICATE != certificate.type) {
            goto ExitFail;
        }
        status = AJ_KeyInfoGet(&pub, AJ_KEYINFO_ECDSA_CA_PUB, &certificate.issuer);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerHandleSendMemberships(msg=%p, reply=%p): Unknown issuer\n", msg, reply));
            goto ExitFail;
        }
        status = AJ_X509Verify(&certificate, &pub);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerHandleSendMemberships(msg=%p, reply=%p): Certificate invalid\n", msg, reply));
            goto ExitFail;
        }
        AJ_InfoPrintf(("AJ_PeerHandleSendMemberships(msg=%p, reply=%p): Certificate valid\n", msg, reply));
        //TODO - Save the digest to compare with AUTH_DATA
        identity.level = AJ_SESSION_AUTHENTICATED;
        identity.type = AJ_ID_TYPE_GUILD;
        identity.data = (uint8_t*) &certificate.guild;
        identity.size = sizeof (AJ_GUID);
        AJ_AuthRecordApply(&identity, msg->sender);
        break;

    case SEND_AUTH_DATA:
        status = AJ_UnmarshalVariant(msg, (const char**) &variant);
        if (AJ_OK != status) {
            goto ExitFail;
        }
        if (0 != strncmp(variant, "ayay(yv)", 8)) {
            goto ExitFail;
        }
        break;

    default:
        goto ExitFail;
        break;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container3);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container2);
    if (AJ_OK != status) {
        goto ExitFail;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto ExitFail;
    }

    status = AJ_MarshalReplyMsg(msg, reply);

    return status;

ExitFail:

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_PeerHandleSendMembershipsReply(AJ_Message* msg)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_PeerHandleSendMembershipsReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): error=%s.\n", msg, msg->error));
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else {
            status = AJ_ERR_SECURITY;
            HandshakeComplete(status);
        }
        return status;
    }

    /*
     * Attempt to send more.
     */
    SendMemberships(msg);

    return AJ_OK;
}

