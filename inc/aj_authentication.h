#ifndef _AJ_AUTHENTICATION_H
#define _AJ_AUTHENTICATION_H

/**
 * @file aj_authentication.h
 * @defgroup aj_authentication Implementation of Authentication mechanisms
 * @{
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

#include "aj_bus.h"
#include "aj_config.h"
#include "aj_target.h"
#include "aj_crypto.h"
#include "aj_crypto_ecc.h"
#include "aj_crypto_sha2.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The key exchange is in the 16 MSB */
#define AUTH_KEYX_ECDHE        0x00400000

/* The key authentication suite is in the 16 LSB */
#define AUTH_SUITE_ECDHE_NULL  (AUTH_KEYX_ECDHE | 0x0001)
#define AUTH_SUITE_ECDHE_PSK   (AUTH_KEYX_ECDHE | 0x0002)
#define AUTH_SUITE_ECDHE_ECDSA (AUTH_KEYX_ECDHE | 0x0004)

#define AJ_AUTH_SUITES_NUM     3    /**< Number of supported authentication suites */

#define AUTH_CLIENT            0
#define AUTH_SERVER            1

/*
 * We now define two versions of conversation hash: one that only hashes
 * things inside KeyExchanger, used in authentication versions 3 and below, and
 * the entire authentication conversation, used starting with version 4. These
 * constants are used internally for calls to UpdateHash to indicate which
 * version of the conversation hash a particular call pertains to.
 *
 * To stay consistent with the authentication version numbers, these are called
 * V1 and V4.
 */
#define CONVERSATION_V1 ((uint32_t)0x0000)
#define CONVERSATION_V4 ((uint32_t)0x0004)

/*
 * Message type headers. All underlying values must fit into a uint8_t.
 */
typedef enum {
    EXCHANGEGUIDSREQUEST,
    EXCHANGEGUIDSREPLY,
    GENSESSIONKEYREQUEST,
    GENSESSIONKEYREPLY,
    EXCHANGESUITESREQUEST,
    EXCHANGESUITESREPLY,
    KEYEXCHANGEREQUEST,
    KEYEXCHANGEREPLY,
    VERIFIER,
    PSK,
    ECDSA
} HashHeader;

typedef struct _KeyExchangeContext {
    AJ_ECCPublicKey pub;
    AJ_ECCPrivateKey prv;
} KeyExchangeContext;

/**
 * Context for PSK authentication
 * Memory is not allocated and copied
 * The pointer addresses memory that exists in the lifetime of its usage
 */
typedef struct _PSKContext {
    uint8_t* hint;                                 /**< PSK hint */
    size_t size;                                   /**< Size of PSK hint */
} PSKContext;

typedef struct _ECDSAContext {
    AJ_ECCPublicKey issuer;                        /**< Certificate issuer */
    AJ_ECCPublicKey subject;                       /**< Certificate subject */
    uint8_t manifest[SHA256_DIGEST_LENGTH];        /**< Manifest digest */
} ECDSAContext;

typedef struct _KeyAuthenticationContext {
    PSKContext psk;                                /**< Context for PSK authentication */
    ECDSAContext ecdsa;                            /**< Context for ECDSA authentication */
} KeyAuthenticationContext;

/**
 * Authentication context
 */
typedef struct _AJ_AuthenticationContext {
    AJ_BusAttachment* bus;                         /**< Bus attachement - required for auth callbacks */
    uint8_t role;                                  /**< Role (client or server) */
    uint32_t suite;                                /**< Authentication suite */
    uint32_t version;                              /**< Protocol version */
    AJ_SHA256_Context hash;                        /**< Running hash of exchanged messages */
    KeyExchangeContext kectx;                      /**< Context for key exchange step */
    KeyAuthenticationContext kactx;                /**< Context for key authentication step */
    uint8_t mastersecret[AJ_MASTER_SECRET_LEN];    /**< Master secret */
    uint32_t expiration;                           /**< Master secret expiration */
} AJ_AuthenticationContext;

/**
 * Marshal a key exchange message
 *
 * @param ctx          The authentication context
 * @param msg          The outgoing message
 *
 * @return
 *         - AJ_OK on success
 *         - An error status otherwise
 */
AJ_Status AJ_KeyExchangeMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg);

/**
 * Unmarshal a key exchange message
 *
 * @param ctx          The authentication context
 * @param msg          The incoming message
 *
 * @return
 *         - AJ_OK on success
 *         - An error status otherwise
 */
AJ_Status AJ_KeyExchangeUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg);

/**
 * Marshal a key authentication message
 *
 * @param ctx          The authentication context
 * @param msg          The outgoing message
 *
 * @return
 *         - AJ_OK on success
 *         - An error status otherwise
 */
AJ_Status AJ_KeyAuthenticationMarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg);

/**
 * Unmarshal a key authentication message
 *
 * @param ctx          The authentication context
 * @param msg          The incoming message
 *
 * @return
 *         - AJ_OK on success
 *         - An error status otherwise
 */
AJ_Status AJ_KeyAuthenticationUnmarshal(AJ_AuthenticationContext* ctx, AJ_Message* msg);

/**
 * Check if an authentication suite is available
 *
 * @param suite        The authentication suite to check
 * @param version      The authentication protocol version
 *
 * @return  Return true or false
 */
uint8_t AJ_IsSuiteEnabled(uint32_t suite, uint32_t version);

/**
 * Enable an authentication suite
 *
 * @param suite        The authentication suite to enable
 */
void AJ_EnableSuite(uint32_t suite);


/**
 * Initialize/reset a conversation hash
 *
 * @param ctx          The authentication context
 *
 */
void AJ_ConversationHash_Initialize(AJ_AuthenticationContext* ctx);

/**
 * Update the conversation hash with a header
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param hashHeader            The header to hash
 *
 */
void AJ_ConversationHash_Update_HashHeader(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, HashHeader hashHeader);

/**
 * Update the conversation hash with a uint8_t
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param byte                  The byte to hash
 *
 */
void AJ_ConversationHash_Update_UInt8(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, uint8_t byte);

/**
 * Update the conversation hash with a byte array
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param buf                   The input array to hash
 * @param bufSize               The size of buf
 *
 */
void AJ_ConversationHash_Update_UInt8Array(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const uint8_t* buf, size_t bufSize);

/**
 * Update the conversation hash with a string. This function does not assume a null-terminated
 * string; it will hash exactly the number of characters indicated by strSize.
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param str                   The string content to hash
 * @param strSize               The length of the string
 *
 */
void AJ_ConversationHash_Update_String(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const char* str, size_t strSize);

/**
 * Update the conversation hash with a message argument (AJ_Arg). This will hash first
 * the typeId byte of the argument and then the argument content.
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param msg                   The AJ_Message from which the arg came
 * @param arg                   The AJ_Arg to hash
 *
 */
void AJ_ConversationHash_Update_Arg(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg, AJ_Arg* arg);

/**
 * Update the conversation hash with a message. This extracts the array of arguments
 * for the message and hashes them. No other content from the message is included.
 *
 * The provided message will have AJ_ResetArgs called on it, so after this call, any unmarshal calls
 * to the msg object will start with the first argument.
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param msg                   The pointer to a message that was unmarshaled by an earlier call to AJ_UnmarshalMsg
 *
 */
void AJ_ConversationHash_Update_UnmarshaledMessage(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg);

/**
 * Update the conversation hash with a message. This extracts the array of arguments
 * for the message and hashes them. No other content from the message is included.
 *
 * The provided message will not be altered by this call.
 *
 * @param ctx                    The authentication context
 * @param conversationVersion    The minimum authentication version which applies to this update
 * @param msg                    The pointer to a message that was put together with one or more AJ_Marshal* calls
 *
 */
void AJ_ConversationHash_Update_MarshaledMessage(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg);


/**
 * Get the conversation hash
 *
 * @param ctx           The authentication context
 * @param digest        The buffer to receive the digest. Must be of SHA256_DIGEST_LENGTH
 * @param keepAlive     Whether or not to keep the digest alive for continuing digest
 */
void AJ_ConversationHash_GetDigest(AJ_AuthenticationContext* ctx, uint8_t* digest, const uint8_t keepAlive);


#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
