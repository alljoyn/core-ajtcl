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

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_bus.h>
#include <ajtcl/aj_msg.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_guid.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_std.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_authorisation.h>
#include <ajtcl/aj_security.h>
#include <ajtcl/aj_conversationhash.h>

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
#define MAX_KEYGEN_VERSION  0x00

/*
 * The base authentication version number
 */
#define MIN_AUTH_VERSION  0x0002
#define MAX_AUTH_VERSION  0x0004

#define REQUIRED_AUTH_VERSION  (((uint32_t)MAX_AUTH_VERSION << 16) | MIN_KEYGEN_VERSION)

#define SEND_MEMBERSHIPS_NONE  0
#define SEND_MEMBERSHIPS_MORE  1
#define SEND_MEMBERSHIPS_LAST  2

static AJ_Status SaveMasterSecret(const AJ_GUID* peerGuid, uint32_t expiration);
static AJ_Status SaveECDSAContext(const AJ_GUID* peerGuid, uint32_t expiration);
static AJ_Status ExchangeSuites(AJ_Message* msg);
static AJ_Status KeyExchange(AJ_BusAttachment* bus);
static AJ_Status KeyAuthentication(AJ_Message* msg);
static AJ_Status GenSessionKey(AJ_Message* msg);
static AJ_Status SendMemberships(AJ_Message* msg);

typedef enum {
    AJ_AUTH_NONE,
    AJ_AUTH_EXCHANGED,
    AJ_AUTH_SUCCESS
} HandshakeState;

typedef struct _PeerContext {
    HandshakeState state;
    AJ_BusAuthPeerCallback callback; /* Callback function to report completion */
    void* cbContext;                 /* Context to pass to the callback function */
    const AJ_GUID* peerGuid;         /* GUID pointer for the currently authenticating peer */
    const char* peerName;            /* Name of the peer being authenticated */
    AJ_Time timer;                   /* Timer for detecting failed authentication attempts */
    char nonce[2 * AJ_NONCE_LEN + 1];   /* Nonce as ascii hex */
} PeerContext;

static PeerContext peerContext;
static AJ_AuthenticationContext authContext = { 0 };
static uint8_t sentManifests = FALSE;

static uint32_t GetAcceptableVersion(uint32_t srcV)
{
    uint16_t authV = AJ_UNPACK_AUTH_VERSION(srcV);
    uint16_t keyV = AJ_UNPACK_KEYGEN_VERSION(srcV);

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

    data[0] = authContext.mastersecret;
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

    status = AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), outBuf, AJ_SESSION_KEY_LEN + AJ_VERIFIER_LEN);
    /*
     * Store the session key and compose the verifier string.
     */
    if (status == AJ_OK) {
        status = AJ_SetSessionKey(peerName, outBuf, role, authContext.version);
    }
    if (status == AJ_OK) {
        memmove(outBuf, outBuf + AJ_SESSION_KEY_LEN, AJ_VERIFIER_LEN);
        status = AJ_RawToHex(outBuf, AJ_VERIFIER_LEN, (char*) outBuf, len, FALSE);
    }
    AJ_InfoPrintf(("KeyGen Verifier = %s.\n", outBuf));
    return status;
}

void AJ_ClearSentManifests()
{
    sentManifests = FALSE;
}

void AJ_ClearAuthContext()
{
    /* Free issuers, hash, and PSK */
    AJ_Free(authContext.kactx.ecdsa.key);
    if (authContext.hash) {
        AJ_SHA256_Final(authContext.hash, NULL);
    }
    AJ_ASSERT(((NULL == authContext.kactx.psk.hint) && (authContext.kactx.psk.hintSize == 0)) ||
              ((NULL != authContext.kactx.psk.hint) && (authContext.kactx.psk.hintSize > 0)));
    AJ_Free(authContext.kactx.psk.hint);
    if (NULL != authContext.kactx.psk.key) {
        AJ_ASSERT(authContext.kactx.psk.keySize > 0);
        AJ_MemZeroSecure(authContext.kactx.psk.key, authContext.kactx.psk.keySize);
        AJ_Free(authContext.kactx.psk.key);
    }

    memset(&peerContext, 0, sizeof (PeerContext));
    memset(&authContext, 0, sizeof (AJ_AuthenticationContext));
}

static void HandshakeComplete(AJ_Status status)
{
    AJ_InfoPrintf(("HandshakeComplete(status=%d.)\n", status));

    /* If ECDSA/PSK failed, try NULL */
    if ((AJ_OK != status) &&
        (AUTH_SUITE_ECDHE_NULL != authContext.suite) &&
        AJ_IsSuiteEnabled(authContext.bus, AUTH_SUITE_ECDHE_NULL, AJ_UNPACK_AUTH_VERSION(authContext.version))) {
        if (AUTH_CLIENT == authContext.role) {
            authContext.suite = AUTH_SUITE_ECDHE_NULL;
            KeyExchange(authContext.bus);
        }
        return;
    }

    if ((AJ_OK == status) && authContext.expiration) {
        status = SaveMasterSecret(peerContext.peerGuid, authContext.expiration);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("HandshakeComplete(status=%d): Save master secret error\n", status));
            goto Exit;
        }
        if (AUTH_SUITE_ECDHE_ECDSA == authContext.suite) {
            status = SaveECDSAContext(peerContext.peerGuid, authContext.expiration);
            if (AJ_OK != status) {
                AJ_WarnPrintf(("HandshakeComplete(status=%d): Save ecdsa context error\n", status));
                goto Exit;
            }
        }
    }

Exit:
    /* Policy no longer needed in memory */
    AJ_PolicyUnload();
    if (peerContext.callback) {
        peerContext.callback(peerContext.cbContext, status);
    }
    AJ_ClearAuthContext();
}

static AJ_Status SaveMasterSecret(const AJ_GUID* peerGuid, uint32_t expiration)
{
    AJ_Status status;

    AJ_InfoPrintf(("SaveMasterSecret(peerGuid=%p, expiration=%d)\n", peerGuid, expiration));

    if (NULL == peerGuid) {
        return AJ_ERR_SECURITY;
    }
    /*
     * If the authentication was succesful write the credentials for the authenticated peer to
     * NVRAM otherwise delete any stale credentials that might be stored.
     */
    if (AJ_AUTH_SUCCESS == peerContext.state) {
        status = AJ_CredentialSetPeer(AJ_GENERIC_MASTER_SECRET, peerGuid, expiration, authContext.mastersecret, AJ_MASTER_SECRET_LEN);
    } else {
        AJ_WarnPrintf(("SaveMasterSecret(peerGuid=%p, expiration=%d): Invalid state\n", peerGuid, expiration));
        AJ_CredentialDeletePeer(peerGuid);
    }

    return status;
}

static AJ_Status LoadMasterSecret(const AJ_GUID* peerGuid)
{
    AJ_Status status;
    uint32_t expiration;
    AJ_CredField data;

    AJ_InfoPrintf(("LoadMasterSecret(peerGuid=%p)\n", peerGuid));

    if (NULL == peerGuid) {
        return AJ_ERR_SECURITY;
    }
    /* Write directly to mastersecret buffer */
    data.size = AJ_MASTER_SECRET_LEN;
    data.data = authContext.mastersecret;
    status = AJ_CredentialGetPeer(AJ_GENERIC_MASTER_SECRET, peerGuid, &expiration, &data);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_CredentialExpired(expiration);

    return status;
}

static AJ_Status SaveECDSAContext(const AJ_GUID* peerGuid, uint32_t expiration)
{
    AJ_Status status;

    AJ_InfoPrintf(("SaveECDSAContext(peerGuid=%p, expiration=%d)\n", peerGuid, expiration));

    if (NULL == peerGuid) {
        return AJ_ERR_SECURITY;
    }

    if ((AJ_AUTH_SUCCESS == peerContext.state) && (authContext.kactx.ecdsa.thumbprintSize > 0)) {
        status = AJ_CredentialSetPeer(AJ_GENERIC_ECDSA_THUMBPRINT, peerGuid, expiration, authContext.kactx.ecdsa.thumbprint, (uint16_t)authContext.kactx.ecdsa.thumbprintSize);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_CredentialSetPeer(AJ_GENERIC_ECDSA_KEYS, peerGuid, expiration, (uint8_t*) authContext.kactx.ecdsa.key, (uint16_t) (authContext.kactx.ecdsa.num * sizeof (AJ_ECCPublicKey)));
        if (AJ_OK != status) {
            return status;
        }
    }

    return status;
}

static AJ_Status LoadECDSAContext(const AJ_GUID* peerGuid)
{
    AJ_Status status;
    AJ_CredField data;

    AJ_InfoPrintf(("LoadECDSAContext(peerGuid=%p)\n", peerGuid));

    /* Check if we have a stored identity thumbprint */
    data.size = AJ_SHA256_DIGEST_LENGTH;
    data.data = authContext.kactx.ecdsa.thumbprint;
    status = AJ_CredentialGetPeer(AJ_GENERIC_ECDSA_THUMBPRINT, peerGuid, NULL, &data);
    if (AJ_OK == status) {
        authContext.kactx.ecdsa.thumbprintSize = data.size;
    } else {
        peerContext.state = AJ_AUTH_SUCCESS;
        return AJ_OK;
    }

    /* If we have an identity certificate thumbprint, we require stored public keys */
    data.size = 0;
    /* Keys is NULL, AJ_CredentialGetPeer will allocate the memory */
    data.data = (uint8_t*) authContext.kactx.ecdsa.key;
    status = AJ_CredentialGetPeer(AJ_GENERIC_ECDSA_KEYS, peerGuid, NULL, &data);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != (data.size % sizeof (AJ_ECCPublicKey))) {
        /* Keys corrupted */
        return AJ_ERR_INVALID;
    }
    authContext.kactx.ecdsa.key = (AJ_ECCPublicKey*) data.data;
    authContext.kactx.ecdsa.num = data.size / (sizeof (AJ_ECCPublicKey));
    authContext.suite = AUTH_SUITE_ECDHE_ECDSA;
    /* Set expiration to zero so we don't resave the credential */
    authContext.expiration = 0;
    peerContext.state = AJ_AUTH_SUCCESS;

    return status;
}

static AJ_Status HandshakeTimeout() {
    uint8_t zero[sizeof (AJ_GUID)];
    memset(zero, 0, sizeof (zero));
    /*
     * If handshake started, check peer is still around
     * If peer disappeared, AJ_GUID_DeleteNameMapping writes zeros
     */
    if (peerContext.peerGuid) {
        if (0 == memcmp(peerContext.peerGuid, zero, sizeof (zero))) {
            AJ_WarnPrintf(("AJ_HandshakeTimeout(): Peer disappeared\n"));
            peerContext.peerGuid = NULL;
            HandshakeComplete(AJ_ERR_TIMEOUT);
            return AJ_ERR_TIMEOUT;
        }
    }
    if (AJ_GetElapsedTime(&peerContext.timer, TRUE) >= AJ_MAX_AUTH_TIME) {
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
    if (!peerContext.peerGuid) {
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
    if ((NULL == peerGuid) || (peerGuid != peerContext.peerGuid)) {
        AJ_WarnPrintf(("AJ_HandshakeValid(peerGuid=%p): Invalid peer guid\n", peerGuid));
        return AJ_ERR_RESOURCES;
    }

    return AJ_OK;
}

static AJ_Status HashGuids(AJ_AuthenticationContext* ctx, const AJ_GUID* remoteGuid)
{
    AJ_GUID localGuid;
    AJ_Status status;
    uint8_t authVersionLE[4];

    AJ_ASSERT(remoteGuid != NULL);
    AJ_ASSERT(AJ_ConversationHash_IsInitialized(ctx));

    /* Auth version is a 32-bit integer, we hash it in little endian order. */
    HostU32ToLittleEndianU8(&(ctx->version), 1, authVersionLE);
    AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, authVersionLE, sizeof(authVersionLE));

    status = AJ_GetLocalGUID(&localGuid);
    if (AJ_OK != status) {
        return status;
    }

    if (ctx->role == AUTH_CLIENT) {
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, (uint8_t*)&localGuid, AJ_GUID_LEN);
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, (uint8_t*)remoteGuid, AJ_GUID_LEN);
    } else {
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, (uint8_t*)remoteGuid, AJ_GUID_LEN);
        AJ_ConversationHash_Update_UInt8Array(ctx, CONVERSATION_V4, (uint8_t*)&localGuid, AJ_GUID_LEN);
    }

    return AJ_OK;
}

AJ_Status AJ_PeerAuthenticate(AJ_BusAttachment* bus, const char* peerName, AJ_PeerAuthenticateCallback callback, void* cbContext)
{
    AJ_Status status;
    AJ_Message msg;
    char guidStr[2 * AJ_GUID_LEN + 1];
    AJ_GUID localGuid;

    AJ_InfoPrintf(("PeerAuthenticate(bus=%p, peerName=\"%s\", callback=%p, cbContext=%p)\n",
                   bus, peerName, callback, cbContext));

    /*
     * If handshake in progress and not timed-out
     */
    if (peerContext.peerGuid) {
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
    AJ_ClearSentManifests();
    peerContext.callback = callback;
    peerContext.cbContext = cbContext;
    peerContext.peerName = peerName;
    AJ_InitTimer(&peerContext.timer);
    authContext.bus = bus;
    authContext.role = AUTH_CLIENT;

    /* Load policy into memory */
    status = AJ_PolicyLoad();
    if (AJ_OK != status) {
        AJ_InfoPrintf(("PeerAuthenticate(): No policy\n"));
    }

    if (bus->pwdCallback) {
        AJ_EnableSuite(bus, AUTH_SUITE_ECDHE_PSK);
        AJ_EnableSuite(bus, AUTH_SUITE_ECDHE_SPEKE);
    }

    /*
     * Kick off authentication with an ExchangeGUIDS method call
     */
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_EXCHANGE_GUIDS, peerName, 0, AJ_NO_FLAGS, AJ_CALL_TIMEOUT);

    if (AJ_OK != status) {
        return status;
    }
    status = AJ_GetLocalGUID(&localGuid);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    if (AJ_OK != status) {
        return status;
    }
    authContext.version = REQUIRED_AUTH_VERSION;
    status = AJ_MarshalArgs(&msg, "su", guidStr, authContext.version);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * Hashing the contents of the ExchangeGuids call is handled differently
     * from the other messages, since the ExchangeGuids call must be
     * idempotent. The conversation hash state is initialized in a subsequent
     * call, in either ExchangeSuites or GenSessionKey (depending on whether
     * the peers share a key). At that time both GUIDs and the authentication
     * version are hashed, capturing the information from ExchangeGuids in the
     * conversation hash.
     */

    return AJ_DeliverMsg(&msg);
}

AJ_Status AJ_PeerHandleExchangeGUIDs(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    char guidStr[33];
    char* str;
    AJ_GUID remoteGuid;
    AJ_GUID localGuid;

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p)\n", msg, reply));

    /*
     * If handshake in progress and not timed-out
     */
    if (peerContext.peerGuid) {
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
    AJ_ClearSentManifests();
    AJ_InitTimer(&peerContext.timer);
    authContext.bus = msg->bus;
    authContext.role = AUTH_SERVER;

    /* Load policy into memory */
    status = AJ_PolicyLoad();
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): No policy\n", msg, reply));
    }

    if (msg->bus->pwdCallback) {
        AJ_EnableSuite(msg->bus, AUTH_SUITE_ECDHE_PSK);
        AJ_EnableSuite(msg->bus, AUTH_SUITE_ECDHE_SPEKE);
    }

    status = AJ_UnmarshalArgs(msg, "su", &str, &authContext.version);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Unmarshal error\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = AJ_GUID_FromString(&remoteGuid, str);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Invalid GUID\n", msg, reply));
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
    status = AJ_GUID_AddNameMapping(msg->bus, &remoteGuid, msg->sender, NULL);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Add name mapping error\n", msg, reply));
        HandshakeComplete(AJ_ERR_RESOURCES);
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }
    peerContext.peerGuid = AJ_GUID_Find(msg->sender);
    /*
     * Reset access control from previous peer
     */
    AJ_AccessControlReset(msg->sender);

    /*
     * If we have a mastersecret stored - use it
     */
    status = LoadMasterSecret(peerContext.peerGuid);
    if (AJ_OK == status) {
        status = LoadECDSAContext(peerContext.peerGuid);
    }
    if (AJ_OK != status) {
        /* Credential expired or failed to load */
        AJ_CredentialDeletePeer(peerContext.peerGuid);
        /* Clear master secret buffer */
        AJ_MemZeroSecure(authContext.mastersecret, AJ_MASTER_SECRET_LEN);
    }

    /*
     * We are not currently negotiating versions so we tell the peer what version we require.
     */
    authContext.version = GetAcceptableVersion(authContext.version);
    if (0 == authContext.version) {
        authContext.version = REQUIRED_AUTH_VERSION;
    }
    AJ_InfoPrintf(("AJ_PeerHandleExchangeGuids(msg=%p, reply=%p): Version %x\n", msg, reply, authContext.version));

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_GetLocalGUID(&localGuid);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalArgs(reply, "su", guidStr, authContext.version);
    if (AJ_OK != status) {
        goto Exit;
    }

    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_PeerHandleExchangeGUIDsReply(AJ_Message* msg)
{
    AJ_Status status;
    const char* guidStr;
    AJ_GUID remoteGuid;

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
    if (peerContext.peerGuid) {
        status = HandshakeTimeout();
        if (AJ_ERR_TIMEOUT != status) {
            AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Handshake in progress\n", msg));
            return AJ_ERR_RESOURCES;
        }
    }

    status = AJ_UnmarshalArgs(msg, "su", &guidStr, &authContext.version);
    if (status != AJ_OK) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Unmarshal error\n", msg));
        goto Exit;
    }
    authContext.version = GetAcceptableVersion(authContext.version);
    if (0 == authContext.version) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Invalid version\n", msg));
        goto Exit;
    }
    status = AJ_GUID_FromString(&remoteGuid, guidStr);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Invalid GUID\n", msg));
        goto Exit;
    }

    /*
     * Two name mappings to add, the well known name, and the unique name from the message.
     */
    status = AJ_GUID_AddNameMapping(msg->bus, &remoteGuid, msg->sender, peerContext.peerName);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGUIDsReply(msg=%p): Add name mapping error\n", msg));
        goto Exit;
    }
    /*
     * Remember which peer is being authenticated
     */
    peerContext.peerGuid = AJ_GUID_Find(msg->sender);
    /*
     * Reset access control from previous peer
     */
    AJ_AccessControlReset(msg->sender);

    /*
     * If we have a mastersecret stored - use it
     */
    status = LoadMasterSecret(peerContext.peerGuid);
    if (AJ_OK == status) {
        status = LoadECDSAContext(peerContext.peerGuid);
    }
    if (AJ_OK == status) {
        status = GenSessionKey(msg);
        return status;
    } else {
        /* Credential expired or failed to load */
        AJ_CredentialDeletePeer(peerContext.peerGuid);
        /* Clear master secret buffer */
        AJ_MemZeroSecure(authContext.mastersecret, AJ_MASTER_SECRET_LEN);
    }

    /*
     * Start the ALLJOYN conversation
     */
    status = ExchangeSuites(msg);
    return status;

Exit:
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

    authContext.role = AUTH_CLIENT;

    /*
     * Send suites in this priority order
     */
    if (AJ_IsSuiteEnabled(msg->bus, AUTH_SUITE_ECDHE_ECDSA, AJ_UNPACK_AUTH_VERSION(authContext.version))) {
        suites[num++] = AUTH_SUITE_ECDHE_ECDSA;
    }
    if (AJ_IsSuiteEnabled(msg->bus, AUTH_SUITE_ECDHE_PSK, AJ_UNPACK_AUTH_VERSION(authContext.version))) {
        suites[num++] = AUTH_SUITE_ECDHE_PSK;
    }
    if (AJ_IsSuiteEnabled(msg->bus, AUTH_SUITE_ECDHE_SPEKE, AJ_UNPACK_AUTH_VERSION(authContext.version))) {
        suites[num++] = AUTH_SUITE_ECDHE_SPEKE;
    }
    if (AJ_IsSuiteEnabled(msg->bus, AUTH_SUITE_ECDHE_NULL, AJ_UNPACK_AUTH_VERSION(authContext.version))) {
        suites[num++] = AUTH_SUITE_ECDHE_NULL;
    }
    if (!num) {
        AJ_WarnPrintf(("ExchangeSuites(msg=%p): No suites available\n", msg));
        goto Exit;
    }
    status = AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_EXCHANGE_SUITES, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("ExchangeSuites(msg=%p): Marshal error\n", msg));
        goto Exit;
    }
    status = AJ_MarshalArgs(&call, "au", suites, num * sizeof (uint32_t));
    if (AJ_OK != status) {
        AJ_WarnPrintf(("ExchangeSuites(msg=%p): Marshal error\n", msg));
        goto Exit;
    }

    /*
     * Initialize conversation hash and hash GUIDs.
     * May have already been done by GenSessionKey.
     */
    if (!AJ_ConversationHash_IsInitialized(&authContext)) {
        status = AJ_ConversationHash_Initialize(&authContext);
        if (AJ_OK != status) {
            goto Exit;
        }
        status = HashGuids(&authContext, peerContext.peerGuid);
        if (AJ_OK != status) {
            goto Exit;
        }
    }

    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, &call, HASH_MSG_MARSHALED);

    return AJ_DeliverMsg(&call);

Exit:
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

    /*
     * Initialize the conversation hash and hash the GUIDs.
     * May have already been done by GenSessionKey.
     */
    if (!AJ_ConversationHash_IsInitialized(&authContext)) {
        status = AJ_ConversationHash_Initialize(&authContext);
        if (AJ_OK != status) {
            goto Exit;
        }
        status = HashGuids(&authContext, peerGuid);
        if (AJ_OK != status) {
            goto Exit;
        }
    }

    /* Update hash before unmarshalling (endian swaps may occur) */
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    authContext.role = AUTH_SERVER;

    /*
     * Receive suites
     */
    status = AJ_UnmarshalArgs(msg, "au", &suites, &numsuites);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuites(msg=%p, reply=%p): Unmarshal error\n", msg, reply));
        goto Exit;
    }
    numsuites /= sizeof (uint32_t);

    /*
     * Calculate common suites
     */
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalContainer(reply, &array, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Iterate through the available suites.
     * If it's enabled, marshal the suite to send to the other peer.
     */
    for (i = 0; i < numsuites; i++) {
        if (AJ_IsSuiteEnabled(msg->bus, suites[i], AJ_UNPACK_AUTH_VERSION(authContext.version))) {
            status = AJ_MarshalArgs(reply, "u", suites[i]);
            if (AJ_OK != status) {
                goto Exit;
            }
        }
    }
    status = AJ_MarshalCloseContainer(reply, &array);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeSuites(msg=%p, reply=%p): Marshal error\n", msg, reply));
        goto Exit;
    }

    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);

    AJ_InfoPrintf(("Exchange Suites Complete\n"));
    return status;

Exit:

    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeSuites(msg=%p, reply=%p): Marshal error\n", msg, reply));
    }

    HandshakeComplete(AJ_ERR_SECURITY);
    status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    if (AJ_OK == status) {
        AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);
    }
    return status;
}

AJ_Status AJ_PeerHandleExchangeSuitesReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t* suites;
    size_t numsuites;
    size_t i;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=%p)\n", msg));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    /* Update hash before unmarshalling (endian swaps may occur) */
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=%p): error=%s.\n", msg, msg->error));
        goto Exit;
    }

    /*
     * Receive suites
     */
    status = AJ_UnmarshalArgs(msg, "au", &suites, &numsuites);
    if (AJ_OK != status) {
        goto Exit;
    }
    numsuites /= sizeof (uint32_t);

    /*
     * Double check we can support (ie. that server didn't send something bogus)
     */
    authContext.suite = 0;
    for (i = 0; i < numsuites; i++) {
        if (AJ_IsSuiteEnabled(msg->bus, suites[i], AJ_UNPACK_AUTH_VERSION(authContext.version))) {
            // Pick the highest priority suite, which happens to be the highest integer
            authContext.suite = (suites[i] > authContext.suite) ? suites[i] : authContext.suite;
        }
    }
    if (!authContext.suite) {
        AJ_InfoPrintf(("AJ_PeerHandleExchangeSuitesReply(msg=%p): No common suites\n", msg));
        goto Exit;
    }

    /*
     * Exchange suites complete.
     */
    AJ_InfoPrintf(("Exchange Suites Complete\n"));
    status = KeyExchange(msg->bus);
    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

static AJ_Status AJ_SetKeyAuthContext(AJ_AuthenticationContext* ctx, const char* peerName)
{
    AJ_Status status;

    if (ctx->suite == AUTH_SUITE_ECDHE_SPEKE) {
        status = AJ_GetLocalGUID(&ctx->kactx.speke.localGUID);
        if (status != AJ_OK) {
            return status;
        }
        ctx->kactx.speke.remoteGUID = AJ_GUID_Find(peerName);
        if (ctx->kactx.speke.remoteGUID == NULL) {
            return AJ_ERR_NO_MATCH;
        }
    }
    return AJ_OK;
}

static AJ_Status KeyExchange(AJ_BusAttachment* bus)
{
    AJ_Status status;
    uint8_t suiteb8[sizeof (uint32_t)];
    AJ_Message call;

    AJ_InfoPrintf(("KeyExchange(bus=%p)\n", bus));

    AJ_InfoPrintf(("Authenticating using suite %x\n", authContext.suite));

    /*
     * Send suite and key material
     */
    status = AJ_MarshalMethodCall(bus, &call, AJ_METHOD_KEY_EXCHANGE, peerContext.peerName, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("KeyExchange(bus=%p): Marshal error\n", bus));
        goto Exit;
    }
    status = AJ_MarshalArgs(&call, "u", authContext.suite);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("KeyExchange(bus=%p): Marshal error\n", bus));
        goto Exit;
    }

    status = AJ_SetKeyAuthContext(&authContext, peerContext.peerName);
    if (AJ_OK != status) {
        goto Exit;
    }

    HostU32ToBigEndianU8(&authContext.suite, sizeof (authContext.suite), suiteb8);
    AJ_ConversationHash_Update_UInt8Array(&authContext, CONVERSATION_V1, suiteb8, sizeof (suiteb8));
    status = AJ_KeyExchangeMarshal(&authContext, &call);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("KeyExchange(bus=%p): Key exchange marshal error\n", bus));
        goto Exit;
    }
    AJ_ASSERT(AUTH_CLIENT == authContext.role);
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, &call, HASH_MSG_MARSHALED);

    return AJ_DeliverMsg(&call);

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

AJ_Status AJ_PeerHandleKeyExchange(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    uint8_t suiteb8[sizeof (uint32_t)];
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    /* Update hash before unmarshalling (endian swaps may occur) */
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    /*
     * Receive suite
     */
    status = AJ_UnmarshalArgs(msg, "u", &authContext.suite);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (!AJ_IsSuiteEnabled(msg->bus, authContext.suite, AJ_UNPACK_AUTH_VERSION(authContext.version))) {
        goto Exit;
    }
    HostU32ToBigEndianU8(&authContext.suite, sizeof (authContext.suite), suiteb8);
    AJ_ConversationHash_Update_UInt8Array(&authContext, CONVERSATION_V1, suiteb8, sizeof (suiteb8));

    status = AJ_SetKeyAuthContext(&authContext, msg->sender);
    if (AJ_OK != status) {
        goto Exit;
    }

    /*
     * Receive key material
     */
    status = AJ_KeyExchangeUnmarshal(&authContext, msg);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p): Key exchange unmarshal error\n", msg, reply));
        goto Exit;
    }

    /*
     * Send key material
     */
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalArgs(reply, "u", authContext.suite);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_ConversationHash_Update_UInt8Array(&authContext, CONVERSATION_V1, (uint8_t*)suiteb8, sizeof(suiteb8));
    status = AJ_KeyExchangeMarshal(&authContext, reply);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchange(msg=%p, reply=%p): Key exchange marshal error\n", msg, reply));
        goto Exit;
    }
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);
    peerContext.state = AJ_AUTH_EXCHANGED;
    AJ_InfoPrintf(("Key Exchange Complete\n"));
    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    if (AJ_OK == status) {
        AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);
    }
    return status;
}

AJ_Status AJ_PeerHandleKeyExchangeReply(AJ_Message* msg)
{
    AJ_Status status;
    uint32_t suite;
    uint8_t suiteb8[sizeof (uint32_t)];
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

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

    /* Update hash before unmarshalling (endian swaps may occur) */
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    /*
     * Receive key material
     */
    status = AJ_UnmarshalArgs(msg, "u", &suite);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): Unmarshal error\n", msg));
        goto Exit;
    }
    if (suite != authContext.suite) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): Suite mismatch\n", msg));
        goto Exit;
    }
    HostU32ToBigEndianU8(&suite, sizeof (suite), suiteb8);
    AJ_ConversationHash_Update_UInt8Array(&authContext, CONVERSATION_V1, suiteb8, sizeof(suiteb8));
    status = AJ_KeyExchangeUnmarshal(&authContext, msg);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyExchangeReply(msg=%p): Key exchange unmarshal error\n", msg));
        goto Exit;
    }

    /*
     * Key exchange complete - start the authentication
     */
    peerContext.state = AJ_AUTH_EXCHANGED;
    AJ_InfoPrintf(("Key Exchange Complete\n"));
    status = KeyAuthentication(msg);
    return status;

Exit:
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

    /* FYI: msg is hashed in AJ_PeerHandleKeyExchangeReply, so don't hash it here as well. */

    /*
     * Send authentication material
     */
    status = AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_KEY_AUTHENTICATION, msg->sender, 0, AJ_NO_FLAGS, AJ_AUTH_CALL_TIMEOUT);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_KeyAuthentication(msg=%p): Key authentication marshal error\n", msg));
        goto Exit;
    }
    /* Get the conversation digest before it's updated with this message */
    status = AJ_ConversationHash_GetDigest(&authContext);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_KeyAuthenticationMarshal(&authContext, &call);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_KeyAuthentication(msg=%p): Key authentication marshal error\n", msg));
        goto Exit;
    }

    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, &call, HASH_MSG_MARSHALED);

    return AJ_DeliverMsg(&call);

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

AJ_Status AJ_PeerHandleKeyAuthentication(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    if (AJ_AUTH_EXCHANGED != peerContext.state) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Invalid state\n", msg, reply));
        AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);
        goto Exit;
    }

    /* Get the conversation digest before it's updated with this message */
    status = AJ_ConversationHash_GetDigest(&authContext);
    if (AJ_OK != status) {
        goto Exit;
    }
    /* Update hash before unmarshalling (endian swaps may occur) */
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    /*
     * Receive authentication material
     */
    status = AJ_KeyAuthenticationUnmarshal(&authContext, msg);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Key authentication unmarshal error\n", msg, reply));
        goto Exit;
    }

    /*
     * Send authentication material
     */
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Get the conversation digest before it's updated with this reply */
    status = AJ_ConversationHash_GetDigest(&authContext);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_KeyAuthenticationMarshal(&authContext, reply);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthentication(msg=%p, reply=%p): Key authentication marshal error\n", msg, reply));
        goto Exit;
    }

    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);

    AJ_InfoPrintf(("Key Authentication Complete\n"));
    peerContext.state = AJ_AUTH_SUCCESS;

    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    if (AJ_OK == status) {
        AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);
    }
    return status;
}

AJ_Status AJ_PeerHandleKeyAuthenticationReply(AJ_Message* msg)
{
    AJ_Status status;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);

    AJ_InfoPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p)\n", msg));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): error=%s.\n", msg, msg->error));
        AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);
        if (0 == strncmp(msg->error, AJ_ErrResources, sizeof(AJ_ErrResources))) {
            status = AJ_ERR_RESOURCES;
        } else {
            status = AJ_ERR_SECURITY;
            HandshakeComplete(status);
        }
        return status;
    }

    if (AJ_AUTH_EXCHANGED != peerContext.state) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): Invalid state\n", msg));
        AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);
        goto Exit;
    }

    /* Get the conversation digest before it's updated with this message */
    status = AJ_ConversationHash_GetDigest(&authContext);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Update hash before unmarshalling (endian swaps may occur) */
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    /*
     * Receive authentication material
     */
    status = AJ_KeyAuthenticationUnmarshal(&authContext, msg);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PeerHandleKeyAuthenticationReply(msg=%p): Key authentication unmarshal error\n", msg));
        goto Exit;
    }

    /*
     * Key authentication complete - start the session
     */
    AJ_InfoPrintf(("Key Authentication Complete\n"));
    peerContext.state = AJ_AUTH_SUCCESS;

    status = GenSessionKey(msg);

    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

static AJ_Status GenSessionKey(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message call;
    char guidStr[33];
    AJ_GUID localGuid;

    AJ_InfoPrintf(("GenSessionKey(msg=%p)\n", msg));

    status = AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_GEN_SESSION_KEY, msg->sender, 0, AJ_NO_FLAGS, AJ_CALL_TIMEOUT);
    if (AJ_OK != status) {
        return status;
    }
    /*
     * Marshal local peer GUID, remote peer GUID, and local peer's GUID
     */
    status = AJ_GetLocalGUID(&localGuid);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(&call, "s", guidStr);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_GUID_ToString(peerContext.peerGuid, guidStr, sizeof(guidStr));
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_RandHex(peerContext.nonce, sizeof(peerContext.nonce), AJ_NONCE_LEN);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(&call, "ss", guidStr, peerContext.nonce);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * Initialize the conversation hash and hash the GUIDs.
     * May have already been done by ExchangeSuites.
     */
    if (!AJ_ConversationHash_IsInitialized(&authContext)) {
        status = AJ_ConversationHash_Initialize(&authContext);
        if (AJ_OK != status) {
            return status;
        }
        status = HashGuids(&authContext, peerContext.peerGuid);
        if (AJ_OK != status) {
            return status;
        }
    }

    /* Hash the message */
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, &call, HASH_MSG_MARSHALED);

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

    /*
     * Initialize conversation hash and hash GUIDs.
     * May have already been done by ExchangeSuites.
     */
    if (!AJ_ConversationHash_IsInitialized(&authContext)) {
        status = AJ_ConversationHash_Initialize(&authContext);
        if (AJ_OK != status) {
            goto Exit;
        }
        status = HashGuids(&authContext, peerGuid);
        if (AJ_OK != status) {
            goto Exit;
        }
    }

    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    if (AJ_AUTH_SUCCESS != peerContext.state) {
        /*
         * We don't have a saved master secret and we haven't generated one yet
         */
        AJ_InfoPrintf(("AJ_PeerHandleGenSessionKey(msg=%p, reply=%p): Key not available\n", msg, reply));
        status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrRejected);
        if (AJ_OK == status) {
            AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);
        }
        return status;
    }

    /*
     * Remote peer GUID, Local peer GUID and Remote peer's nonce
     */
    status = AJ_UnmarshalArgs(msg, "sss", &remGuid, &locGuid, &nonce);
    if (AJ_OK != status) {
        goto Exit;
    }

    /*
     * We expect arg[1] to be the local GUID
     */
    status = AJ_GUID_FromString(&guid, locGuid);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_GetLocalGUID(&localGuid);
    if (AJ_OK != status) {
        goto Exit;
    }
    if (0 != memcmp(&guid, &localGuid, sizeof(AJ_GUID))) {
        goto Exit;
    }
    status = AJ_RandHex(peerContext.nonce, sizeof(peerContext.nonce), AJ_NONCE_LEN);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = KeyGen(msg->sender, AJ_ROLE_KEY_RESPONDER, nonce, peerContext.nonce, (uint8_t*)verifier, sizeof(verifier));
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalArgs(reply, "ss", peerContext.nonce, verifier);
    if (AJ_OK != status) {
        goto Exit;
    }
    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);
    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    if (AJ_OK == status) {
        AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, reply, HASH_MSG_MARSHALED);
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
    AJ_Arg key;
    AJ_Message call;
    uint8_t groupKey[AJ_SESSION_KEY_LEN];

    AJ_InfoPrintf(("AJ_PeerHandleGenSessionKeyReply(msg=%p)\n", msg));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    AJ_ConversationHash_Update_Message(&authContext, CONVERSATION_V4, msg, HASH_MSG_UNMARSHALED);

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleGenSessionKeyReply(msg=%p): error=%s.\n", msg, msg->error));
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

    status = AJ_UnmarshalArgs(msg, "ss", &nonce, &remVerifier);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = KeyGen(msg->sender, AJ_ROLE_KEY_INITIATOR, peerContext.nonce, nonce, (uint8_t*)verifier, sizeof(verifier));
    if (AJ_OK != status) {
        goto Exit;
    }
    /*
     * Check verifier strings match as expected
     */
    if (0 != strncmp(remVerifier, verifier, sizeof (verifier))) {
        AJ_WarnPrintf(("AJ_PeerHandleGenSessionKeyReply(): AJ_ERR_SECURITY\n"));
        status = AJ_ERR_SECURITY;
        goto Exit;
    }

    /*
     * Group keys are exchanged via an encrypted message
     */
    status = AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_EXCHANGE_GROUP_KEYS, msg->sender, 0, AJ_FLAG_ENCRYPTED, AJ_CALL_TIMEOUT);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_GetGroupKey(NULL, groupKey);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalArg(&call, AJ_InitArg(&key, AJ_ARG_BYTE, AJ_ARRAY_FLAG, groupKey, sizeof(groupKey)));
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_DeliverMsg(&call);

    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

AJ_Status AJ_PeerHandleExchangeGroupKeys(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_Arg key;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    uint8_t groupKey[AJ_SESSION_KEY_LEN];

    AJ_InfoPrintf(("AJ_PeerHandleExchangeGroupKeys(msg=%p, reply=%p)\n", msg, reply));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGroupKeys(msg=%p): error=%s.\n", msg, msg->error));
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

    status = AJ_UnmarshalArg(msg, &key);
    if (AJ_OK != status) {
        goto Exit;
    }
    /*
     * We expect the key to be 16 bytes
     */
    if (key.len != AJ_SESSION_KEY_LEN) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGroupKeys(): AJ_ERR_INVALID\n"));
        goto Exit;
    }
    status = AJ_SetGroupKey(msg->sender, key.val.v_byte);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_GetGroupKey(NULL, groupKey);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_MarshalArg(reply, AJ_InitArg(&key, AJ_ARG_BYTE, AJ_ARRAY_FLAG, groupKey, sizeof(groupKey)));
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_PolicyApply(&authContext, msg->sender);
    if (AUTH_SUITE_ECDHE_ECDSA != authContext.suite) {
        HandshakeComplete(status);
    }

    /* Search for membership certificates from the beginning */
    authContext.slot = AJ_CREDS_NV_ID_BEGIN;
    authContext.code = SEND_MEMBERSHIPS_NONE;
    status = AJ_CredentialGetNext(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, NULL, &authContext.slot);
    if (AJ_OK == status) {
        /* There is at least one cert to send, we don't know if the last yet */
        authContext.code = SEND_MEMBERSHIPS_MORE;
    }
    status = AJ_OK;

    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
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

    status = AJ_UnmarshalArg(msg, &arg);
    if (AJ_OK != status) {
        goto Exit;
    }
    /*
     * We expect the key to be 16 bytes
     */
    if (arg.len != AJ_SESSION_KEY_LEN) {
        AJ_WarnPrintf(("AJ_PeerHandleExchangeGroupKeysReply(msg=%p): AJ_ERR_INVALID\n", msg));
        goto Exit;
    }
    status = AJ_SetGroupKey(msg->sender, arg.val.v_byte);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_PolicyApply(&authContext, msg->sender);
    if (AJ_OK != status) {
        goto Exit;
    }
    if ((AUTH_SUITE_ECDHE_ECDSA == authContext.suite) && (AJ_UNPACK_AUTH_VERSION(authContext.version) >= CONVERSATION_V4)) {
        /* Search for membership certificates from the beginning */
        authContext.slot = AJ_CREDS_NV_ID_BEGIN;
        authContext.code = SEND_MEMBERSHIPS_NONE;
        status = AJ_CredentialGetNext(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, NULL, &authContext.slot);
        AJ_InfoPrintf(("AJ_PeerHandleExchangeGroupKeysReply(msg=%p): Membership slot %d\n", msg, authContext.slot));
        if (AJ_OK == status) {
            /* There is at least one certificate to send, we don't know if the last yet */
            authContext.code = SEND_MEMBERSHIPS_MORE;
        }

        status = AJ_PeerSendManifests(msg, FALSE);
    } else {
        HandshakeComplete(status);
    }

    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

AJ_Status AJ_PeerSendManifests(AJ_Message* msg, uint8_t outgoing)
{
    AJ_Status status;
    AJ_Message call;
    const AJ_GUID* peerGuid = AJ_GUID_Find(outgoing ? msg->destination : msg->sender);
    AJ_CredField field = { 0, NULL };
    AJ_ManifestArray* manifests = NULL;
    uint8_t mustClearAuthContext = FALSE;

    AJ_InfoPrintf(("AJ_PeerSendManifests(msg=%p, outgoing=%u)\n", msg, outgoing));

    if (sentManifests) {
        /* Already sent. */
        return AJ_OK;
    }

    if (NULL == authContext.bus) {
        status = LoadECDSAContext(peerGuid);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerSendManifests(msg=%p, outgoing=%u): Could not load ECDSA context for peer\n", msg, outgoing));
            return AJ_ERR_SECURITY;
        }
        mustClearAuthContext = TRUE;
    }

    if (AUTH_SUITE_ECDHE_ECDSA != authContext.suite) {
        /* No need to send. */
        status = AJ_OK;
        goto Exit;
    }

    status = AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_SEND_MANIFESTS, (outgoing ? msg->destination : msg->sender), 0, AJ_FLAG_ENCRYPTED, AJ_AUTH_CALL_TIMEOUT);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_CredentialGet(AJ_CRED_TYPE_MANIFESTS, NULL, NULL, &field);
    if (AJ_OK == status) {
        status = AJ_ManifestArrayFromBuffer(&manifests, &field);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerSendManifests(msg=%p): Manifests buffer failed\n", msg));
            goto Exit;
        }
    }

    status = AJ_ManifestArrayMarshal(manifests, &call);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerSendManifests(msg=%p): Manifests marshal failed\n", msg));
        goto Exit;
    }

Exit:
    AJ_CredFieldFree(&field);
    AJ_ManifestArrayFree(manifests);
    if (AJ_OK == status) {
        status = AJ_DeliverMsg(&call);
        if (AJ_OK == status) {
            sentManifests = TRUE;
        }
    }
    if (mustClearAuthContext) {
        AJ_ClearAuthContext();
    }

    return status;
}

AJ_Status AJ_PeerHandleSendManifests(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    AJ_CredField field = { 0, NULL };
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    AJ_ManifestArray* manifests = NULL;
    uint8_t mustClearAuthContext = FALSE;

    AJ_InfoPrintf(("AJ_PeerHandleSendManifests(msg=%p, reply=%p)\n", msg, reply));

    /*
     * This might get called during handshake, or after. If after, load the ECDSA context
     * so the identity certificate thumbprint is available.
     */
    if (NULL == authContext.bus) {
        status = LoadECDSAContext(peerGuid);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerHandleSendManifests(msg=%p, reply=%p): Could not load ECDSA context for peer\n", msg, reply));
            return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
        }
        mustClearAuthContext = TRUE;
    }

    status = AJ_ManifestArrayUnmarshal(&manifests, msg);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleSendManifests(msg=%p, reply=%p): Manifests unmarshal failed\n", msg, reply));
        goto Exit;
    }
    AJ_ManifestArrayApply(manifests, msg->sender, &authContext);

    AJ_ManifestArrayFree(manifests);
    manifests = NULL;

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleSendManifests(msg=%p, reply=%p): Manifest marshal failed\n", msg, reply));
        goto Exit;
    }
    status = AJ_CredentialGet(AJ_CRED_TYPE_MANIFESTS, NULL, NULL, &field);
    if (AJ_OK == status) {
        status = AJ_ManifestArrayFromBuffer(&manifests, &field);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerHandleSendManifests(msg=%p, reply=%p): Manifests buffer failed\n", msg, reply));
            goto Exit;
        }
    }

    status = AJ_ManifestArrayMarshal(manifests, reply);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleSendManifests(msg=%p, reply=%p): Manifests marshal failed\n", msg, reply));
        goto Exit;
    }
    AJ_ManifestArrayFree(manifests);
    manifests = NULL;

Exit:
    AJ_CredFieldFree(&field);
    AJ_ManifestArrayFree(manifests);
    if (mustClearAuthContext) {
        AJ_ClearAuthContext();
    }
    if (AJ_OK == status) {
        sentManifests = TRUE;
        return status;
    } else {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
    }
}

AJ_Status AJ_PeerHandleSendManifestsReply(AJ_Message* msg)
{
    AJ_Status status;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    AJ_ManifestArray* manifests = NULL;
    uint8_t mustClearAuthContext = FALSE;

    AJ_InfoPrintf(("AJ_PeerHandleSendManifestsReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleSendManifestsReply(msg=%p): error=%s.\n", msg, msg->error));
        goto Exit;
    }

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * This might get called during handshake, or after. If after, load the ECDSA context
     * so the identity certificate thumbprint is available.
     */
    if (NULL == authContext.bus) {
        status = LoadECDSAContext(peerGuid);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerHandleSendManifestsReply(msg=%p): Could not load ECDSA context for peer\n", msg));
            status = AJ_ERR_SECURITY;
            goto Exit;
        }
        mustClearAuthContext = TRUE;
    }

    status = AJ_ManifestArrayUnmarshal(&manifests, msg);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PeerHandleSendManifestsReply(msg=%p): Manifests unmarshal failed\n", msg));
        goto Exit;
    }
    AJ_ManifestArrayApply(manifests, msg->sender, &authContext);
    AJ_ManifestArrayFree(manifests);
    manifests = NULL;

    /* Search for membership certificates from the beginning */
    authContext.slot = AJ_CREDS_NV_ID_BEGIN;
    authContext.code = SEND_MEMBERSHIPS_NONE;
    status = AJ_CredentialGetNext(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, NULL, &authContext.slot);
    AJ_InfoPrintf(("AJ_PeerHandleSendManifestsReply(msg=%p): Membership slot %d\n", msg, authContext.slot));
    if (AJ_OK == status) {
        /* There is at least one cert to send, we don't know if the last yet */
        authContext.code = SEND_MEMBERSHIPS_MORE;
    }
    status = AJ_OK;

Exit:
    AJ_ManifestArrayFree(manifests);
    if (mustClearAuthContext) {
        AJ_ClearAuthContext();
    }
    if (AJ_OK == status) {
        sentManifests = TRUE;
        return SendMemberships(msg);
    } else {
        HandshakeComplete(AJ_ERR_SECURITY);
        return AJ_ERR_SECURITY;
    }
}

static AJ_Status MarshalCertificates(X509CertificateChain* root, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    X509CertificateChain* head;
    uint8_t fmt = CERT_FMT_X509_DER;

    /*
     * X509CertificateChain is root first.
     * The wire protocol requires leaf first,
     * reverse it here, then reverse it back after marshalling.
     */
    root = AJ_X509ReverseChain(root);
    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    head = root;
    while (head) {
        status = AJ_MarshalArgs(msg, "(yay)", fmt, head->certificate.der.data, head->certificate.der.size);
        if (AJ_OK != status) {
            goto Exit;
        }
        head = head->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

Exit:
    root = AJ_X509ReverseChain(root);
    return status;
}

static AJ_Status CommonIssuer(X509CertificateChain* root)
{
    AJ_Status status = AJ_ERR_UNKNOWN;
    X509CertificateChain* node;
    size_t i;

    AJ_ASSERT(root);
    for (i = 1; i < authContext.kactx.ecdsa.num; i++) {
        node = root;
        /* Check if intermediate issuer signed the root */
        if (AJ_OK == AJ_X509Verify(&node->certificate, &authContext.kactx.ecdsa.key[i])) {
            status = AJ_OK;
            goto Exit;
        }
        /* Check if intermediate issuer is a subject */
        while (node && node->certificate.tbs.extensions.ca) {
            if (0 == memcmp(&node->certificate.tbs.publickey, &authContext.kactx.ecdsa.key[i], sizeof (AJ_ECCPublicKey))) {
                status = AJ_OK;
                goto Exit;
            }
            node = node->next;
        }
    }

Exit:
    return status;
}

static AJ_Status MarshalMembership(AJ_Message* msg)
{
    AJ_Status status = AJ_ERR_UNKNOWN;
    AJ_Arg container;
    AJ_CredField data;
    X509CertificateChain* root = NULL;

    AJ_ASSERT(SEND_MEMBERSHIPS_LAST != authContext.code);

    data.size = 0;
    data.data = NULL;
    while ((AJ_ERR_UNKNOWN == status) && (SEND_MEMBERSHIPS_MORE == authContext.code)) {
        /*
         * Read membership certificate at current slot, there should be one.
         * We then check if the root issuer is the same as any of the issuers
         * of the identity certificate (ASACORE-2104)
         */
        status = AJ_CredentialGetNext(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, &data, &authContext.slot);
        authContext.slot++;
        if (AJ_OK == status) {
            status = AJ_X509ChainFromBuffer(&root, &data);
            if (AJ_OK == status) {
                status = CommonIssuer(root);
                AJ_InfoPrintf(("MarshalMembership(msg=%p): Common issuer %s\n", msg, AJ_StatusText(status)));
            }
            if (AJ_OK != status) {
                AJ_CredFieldFree(&data);
                AJ_X509ChainFree(root);
                root = NULL;
                status = AJ_ERR_UNKNOWN;
            }
        } else {
            authContext.code = SEND_MEMBERSHIPS_NONE;
            status = AJ_OK;
        }
    }

    if (SEND_MEMBERSHIPS_NONE == authContext.code) {
        AJ_InfoPrintf(("MarshalMembership(msg=%p): None certificate\n", msg));
        status = AJ_MarshalArgs(msg, "y", authContext.code);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("MarshalMembership(msg=%p): Marshal error\n", msg));
            goto Exit;
        }
        status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("MarshalMembership(msg=%p): Marshal error\n", msg));
            goto Exit;
        }
        status = AJ_MarshalCloseContainer(msg, &container);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("MarshalMembership(msg=%p): Marshal error\n", msg));
            goto Exit;
        }
        return status;
    }

    AJ_ASSERT(SEND_MEMBERSHIPS_MORE == authContext.code);
    /* Find slot of next membership certificate (if available) */
    status = AJ_CredentialGetNext(AJ_CERTIFICATE_MBR_X509 | AJ_CRED_TYPE_CERTIFICATE, NULL, NULL, NULL, &authContext.slot);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("MarshalMembership(msg=%p): Last certificate\n", msg));
        authContext.code = SEND_MEMBERSHIPS_LAST;
    } else {
        AJ_InfoPrintf(("MarshalMembership(msg=%p): More certificate\n", msg));
    }
    /* Marshal code and certificate */
    status = AJ_MarshalArgs(msg, "y", authContext.code);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("MarshalMembership(msg=%p): Marshal error\n", msg));
        goto Exit;
    }
    status = MarshalCertificates(root, msg);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("MarshalMembership(msg=%p): Marshal error\n", msg));
        goto Exit;
    }
    /* Once we send the last code, set it to none so we don't send any more */
    if (SEND_MEMBERSHIPS_LAST == authContext.code) {
        authContext.code = SEND_MEMBERSHIPS_NONE;
    }

Exit:
    AJ_X509ChainFree(root);
    AJ_CredFieldFree(&data);
    return status;
}

static AJ_Status SendMemberships(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Message call;

    AJ_InfoPrintf(("SendMemberships(msg=%p)\n", msg));

    status = AJ_MarshalMethodCall(msg->bus, &call, AJ_METHOD_SEND_MEMBERSHIPS, msg->sender, 0, AJ_FLAG_ENCRYPTED, AJ_AUTH_CALL_TIMEOUT);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("SendMemberships(msg=%p): Marshal error\n", msg));
        goto Exit;
    }

    status = MarshalMembership(&call);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("SendMemberships(msg=%p): Marshal error\n", msg));
        goto Exit;
    }

    return AJ_DeliverMsg(&call);

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}

static void UnmarshalCertificates(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    uint8_t alg;
    DER_Element der;
    X509CertificateChain* root = NULL;
    X509CertificateChain* node = NULL;
    AJ_ECCPublicKey* pub = NULL;
    DER_Element* group;
    uint32_t type;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalArgs(msg, "(yay)", &alg, &der.data, &der.size);
        if (AJ_OK != status) {
            break;
        }
        node = (X509CertificateChain*) AJ_Malloc(sizeof (X509CertificateChain));
        if (NULL == node) {
            AJ_WarnPrintf(("UnmarshalCertificates(msg=%p): Resource error\n", msg));
            goto Exit;
        }
        node->next = root;
        root = node;
        /* Set the der before it's consumed */
        node->certificate.der.size = der.size;
        node->certificate.der.data = der.data;
        status = AJ_X509DecodeCertificateDER(&node->certificate, &der);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("UnmarshalCertificates(msg=%p): Certificate decode failed\n", msg));
            goto Exit;
        }

        /*
         * If this is the first certificate, check the subject public key
         * is the same as the authenticated one (from identity certificate)
         * Also save the group for authorisation check
         */
        if (NULL == node->next) {
            AJ_ASSERT(authContext.kactx.ecdsa.key);
            AJ_ASSERT(authContext.kactx.ecdsa.num);
            if (0 != memcmp((uint8_t*) &node->certificate.tbs.publickey, (uint8_t*) &authContext.kactx.ecdsa.key[0], sizeof (AJ_ECCPublicKey))) {
                AJ_InfoPrintf(("UnmarshalCertificates(msg=%p): Subject invalid\n", msg));
                goto Exit;
            }
            group = &node->certificate.tbs.extensions.group;
            AJ_DumpBytes("GROUP", group->data, group->size);
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        AJ_InfoPrintf(("UnmarshalCertificates(msg=%p): Certificate chain error %s\n", msg, AJ_StatusText(status)));
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);
    if (AJ_OK != status) {
        goto Exit;
    }

    /* Initial chain verification to validate intermediate issuers.
     * Type is ignored for auth version < 4.
     */
    if (AJ_UNPACK_AUTH_VERSION(authContext.version) < CONVERSATION_V4) {
        type = 0;
    } else {
        type = AJ_CERTIFICATE_MBR_X509;
    }
    status = AJ_X509VerifyChain(root, NULL, type);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("UnmarshalCertificates(msg=%p): Certificate chain invalid\n", msg));
        goto Exit;
    }

    /* Verify the root certificate against the stored authorities */
    pub = (AJ_ECCPublicKey*) AJ_Malloc(sizeof (AJ_ECCPublicKey));
    if (NULL == pub) {
        AJ_InfoPrintf(("UnmarshalCertificates(msg=%p): AJ_ERR_RESOURCES\n", msg));
        goto Exit;
    }
    status = AJ_PolicyVerifyCertificate(&root->certificate, pub);
    if (AJ_OK != status) {
        AJ_Free(pub);
        pub = NULL;
        /* Search for the intermediate issuers in the stored authorities */
        status = AJ_PolicyFindAuthority(root);
        if (AJ_OK != status) {
        }
    }
    if (AJ_OK != status) {
        AJ_InfoPrintf(("UnmarshalCertificates(msg=%p): Certificate authority unknown\n", msg));
        goto Exit;
    }
    AJ_InfoPrintf(("UnmarshalCertificates(msg=%p): Certificate chain valid\n", msg));
    AJ_MembershipApply(root, pub, group, msg->sender);

Exit:
    AJ_Free(pub);
    /* Free the cert chain */
    while (root) {
        node = root;
        root = root->next;
        AJ_Free(node);
    }
}

AJ_Status AJ_PeerHandleSendMemberships(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    uint8_t code;

    AJ_InfoPrintf(("AJ_PeerHandleSendMemberships(msg=%p, reply=%p)\n", msg, reply));

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return AJ_MarshalErrorMsg(msg, reply, AJ_ErrResources);
    }

    status = AJ_UnmarshalArgs(msg, "y", &code);
    if (AJ_OK != status) {
        goto Exit;
    }

    AJ_InfoPrintf(("AJ_PeerHandleSendMemberships(msg=%p, reply=%p): Received code %d\n", msg, reply, code));

    if (SEND_MEMBERSHIPS_NONE != code) {
        /*
         * Unmarshal certificate chain, verify and apply membership rules
         * If failure occured (eg. false certificate), the rules will not be applied.
         */
        UnmarshalCertificates(msg);
        if (SEND_MEMBERSHIPS_LAST == code) {
            code = SEND_MEMBERSHIPS_NONE;
        }
        if (SEND_MEMBERSHIPS_LAST == code) {
            code = SEND_MEMBERSHIPS_NONE;
        }
    }

    status = AJ_MarshalReplyMsg(msg, reply);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = MarshalMembership(reply);
    if (AJ_OK != status) {
        goto Exit;
    }

    if ((SEND_MEMBERSHIPS_NONE == authContext.code) && (SEND_MEMBERSHIPS_NONE == code)) {
        /*
         * Nothing more to send or receive. Try to send manifests. Don't call HandshakeComplete
         * until after so the authContext is still present.
         */
        status = AJ_PeerSendManifests(msg, FALSE);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_PeerHandleSendMemberships(msg=%p, reply=%p): Couldn't AJ_PeerSendManifests; got %u\n",
                           msg, reply, status));
        }
        HandshakeComplete(status);

    }

    return status;

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrSecurityViolation);
}

AJ_Status AJ_PeerHandleSendMembershipsReply(AJ_Message* msg)
{
    AJ_Status status;
    const AJ_GUID* peerGuid = AJ_GUID_Find(msg->sender);
    uint8_t code;

    AJ_InfoPrintf(("AJ_PeerHandleSendMembershipsReply(msg=%p)\n", msg));

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_WarnPrintf(("AJ_PeerHandleSendMembershipsReply(msg=%p): error=%s.\n", msg, msg->error));
        goto Exit;
    }

    status = HandshakeValid(peerGuid);
    if (AJ_OK != status) {
        return status;
    }

    status = AJ_UnmarshalArgs(msg, "y", &code);
    if (AJ_OK != status) {
        goto Exit;
    }

    if (SEND_MEMBERSHIPS_NONE != code) {
        /*
         * Unmarshal certificate chain, verify and apply membership rules
         * If failure occured (eg. false certificate), the rules will not be applied.
         */
        UnmarshalCertificates(msg);
        if (SEND_MEMBERSHIPS_LAST == code) {
            code = SEND_MEMBERSHIPS_NONE;
        }
    }

    if ((SEND_MEMBERSHIPS_NONE == authContext.code) && (SEND_MEMBERSHIPS_NONE == code)) {
        /* Nothing more to send or receive */
        HandshakeComplete(status);
        return status;
    } else {
        return SendMemberships(msg);
    }

Exit:
    HandshakeComplete(AJ_ERR_SECURITY);
    return AJ_ERR_SECURITY;
}
