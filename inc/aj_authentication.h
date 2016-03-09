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

#include <ajtcl/aj_bus.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_target.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_sha2.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The key exchange is in the 16 MSB */
#define AUTH_KEYX_ECDHE        0x00400000

/* The key authentication suite is in the 16 LSB */
#define AUTH_SUITE_ECDHE_NULL  (AUTH_KEYX_ECDHE | 0x0001)
#define AUTH_SUITE_ECDHE_PSK   (AUTH_KEYX_ECDHE | 0x0002)
#define AUTH_SUITE_ECDHE_ECDSA (AUTH_KEYX_ECDHE | 0x0004)
#define AUTH_SUITE_ECDHE_SPEKE (AUTH_KEYX_ECDHE | 0x0008)

#define AJ_AUTH_SUITES_NUM     4    /**< Number of supported authentication suites */

#define AUTH_CLIENT            0
#define AUTH_SERVER            1

#define HASH_MSG_UNMARSHALED   ((uint8_t)0)
#define HASH_MSG_MARSHALED     ((uint8_t)1)

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

/* The authentication conversation version is stored in the upper 16
 * bits of the version value, and the keygen version is stored in the
 * lower 16 bits
 */
#define AJ_UNPACK_AUTH_VERSION(v)   ((v) >> 16)
#define AJ_UNPACK_KEYGEN_VERSION(v) ((v) & 0xFFFF)

typedef struct _KeyExchangeContext {
    AJ_ECCPublicKey pub;
    AJ_ECCPrivateKey prv;
} KeyExchangeContext;

/**
 * Size of buffer provided for the PSK when using the V1 callback.
 */
#define PSK_V1_CALLBACK_BUFFER_SIZE ((size_t)128)

/**
 * Context for PSK authentication
 * Memory is allocated and copied, and is cleared and freed by AJ_ClearAuthContext
 */
typedef struct _PSKContext {
    uint8_t* hint;                                 /**< PSK hint */
    size_t hintSize;                               /**< Size of PSK hint */
    uint8_t* key;                                  /**< PSK */
    size_t keySize;                                /**< Size of PSK */
} PSKContext;

typedef struct _ECDSAContext {
    AJ_ECCPublicKey* key;                          /**< Array of public keys (subject + issuers) */
    size_t num;                                    /**< Number of public keys */
    uint8_t thumbprint[AJ_SHA256_DIGEST_LENGTH];   /**< Identity certificate SHA-256 thumbprint */
    size_t thumbprintSize;                         /**< Thumbprint size (should always be 0 or AJ_SHA256_DIGEST_LENGTH) */
} ECDSAContext;

/**
 * Context for EC-SPEKE authentication
 * The local GUID is read from the keystore, so we need to keep it in memory,
 * while the remote GUID is already in memory during authentication.
 */
typedef struct _SPEKEContext {
    AJ_GUID localGUID;                             /**< Our GUID */
    const AJ_GUID* remoteGUID;                     /**< Our peer's GUID */
} SPEKEContext;

/**
 * The KeyAuthenticationContext will hold the suite-specific context,
 * depending on AJ_AuthenticationContext.suite.
 */
typedef struct _KeyAuthenticationContext {
    PSKContext psk;                                /**< Context for PSK authentication */
    ECDSAContext ecdsa;                            /**< Context for ECDSA authentication */
    SPEKEContext speke;                            /**< Context for EC-SPEKE authentication */
} KeyAuthenticationContext;

/**
 * Authentication context
 */
typedef struct _AJ_AuthenticationContext {
    AJ_BusAttachment* bus;                         /**< Bus attachement - required for auth callbacks */
    uint8_t role;                                  /**< Role (client or server) */
    uint32_t suite;                                /**< Authentication suite */
    uint32_t version;                              /**< Protocol version */
    AJ_SHA256_Context* hash;                       /**< Running hash of exchanged messages */
    KeyExchangeContext kectx;                      /**< Context for key exchange step */
    KeyAuthenticationContext kactx;                /**< Context for key authentication step */
    uint8_t mastersecret[AJ_MASTER_SECRET_LEN];    /**< Master secret */
    uint32_t expiration;                           /**< Master secret expiration */
    uint16_t slot;                                 /**< NVRAM slot of membership certificate */
    uint8_t code;                                  /**< Send Membership code (NONE, MORE, LAST) */
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];       /**< Conversation digest */
    uint8_t sensitiveMode;                         /**< Conversation digest tracing sensitive mode */
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
 * @param bus          The bus attachment
 * @param suite        The authentication suite to check
 * @param version      The authentication protocol version
 *
 * @return  Return true or false
 */
uint8_t AJ_IsSuiteEnabled(AJ_BusAttachment* bus, uint32_t suite, uint32_t version);

/**
 * Enable an authentication suite
 *
 * @param bus          The bus attachment
 * @param suite        The authentication suite to enable
 */
void AJ_EnableSuite(AJ_BusAttachment* bus, uint32_t suite);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
