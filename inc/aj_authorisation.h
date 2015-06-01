#ifndef _AJ_AUTHORISATION_H
#define _AJ_AUTHORISATION_H
/**
 * @file aj_authorisation.h
 * @defgroup aj_authorisation Authorisation Support
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

#include "aj_authentication.h"
#include "aj_creds.h"
#include "aj_crypto_ecc.h"
#include "aj_crypto_sha2.h"
#include "aj_guid.h"
#include "aj_msg.h"
#include "aj_target.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AJ_ACCESS_INCOMING           0x1
#define AJ_ACCESS_OUTGOING           0x2

#define AJ_MEMBER_TYPE_ANY             0
#define AJ_MEMBER_TYPE_METHOD          1
#define AJ_MEMBER_TYPE_SIGNAL          2
#define AJ_MEMBER_TYPE_PROPERTY        3
#define AJ_ACTION_PROVIDE            0x1
#define AJ_ACTION_OBSERVE            0x2
#define AJ_ACTION_MODIFY             0x4
typedef struct _AJ_PermissionMember {
    char* mbr;                         /**< Member name */
    uint8_t type;                      /**< Member type (METHOD, SIGNAL, etc.) */
    uint8_t action;                    /**< Action (PROVIDE, OBSERVE, etc.) */
    struct _AJ_PermissionMember* next;
} AJ_PermissionMember;

typedef struct _AJ_PermissionRule {
    char* obj;                         /**< Object name */
    char* ifn;                         /**< Interface name */
    AJ_PermissionMember* members;      /**< Members */
    struct _AJ_PermissionRule* next;
} AJ_PermissionRule;

typedef struct _AJ_Manifest {
    AJ_PermissionRule* rules;          /**< Rules */
} AJ_Manifest;

#define AJ_PEER_TYPE_ALL               0
#define AJ_PEER_TYPE_ANY_TRUSTED       1
#define AJ_PEER_TYPE_FROM_CA           2
#define AJ_PEER_TYPE_WITH_PUBLIC_KEY   3
#define AJ_PEER_TYPE_WITH_MEMBERSHIP   4
typedef struct _AJ_PermissionPeer {
    uint8_t type;                      /**< Peer type */
    AJ_ECCPublicKey* pub;              /**< ECC public key (optional) */
    AJ_GUID* group;                    /**< Group identifier (optional) */
    struct _AJ_PermissionPeer* next;
} AJ_PermissionPeer;

typedef struct _AJ_PermissionACL {
    AJ_PermissionPeer* peers;          /**< Peers */
    AJ_PermissionRule* rules;          /**< Rules */
    struct _AJ_PermissionACL* next;
} AJ_PermissionACL;

typedef struct _AJ_Policy {
    uint16_t specification;            /**< Specification version */
    uint32_t version;                  /**< Policy version */
    AJ_PermissionACL* acls;            /**< ACLs */
} AJ_Policy;

/**
 * Initialise access control list
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_AuthorisationInit();

/**
 * Cleanup access control memory
 */
void AJ_AuthorisationClose();

/**
 * Set the manifest template, called by the application
 *
 * @param manifest     The manifest
 */
void AJ_ManifestTemplateSet(AJ_Manifest* manifest);

/**
 * Marshal the manifest template, set from the application
 *
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestTemplateMarshal(AJ_Message* msg);

/**
 * Calculate manifest digest
 *
 * @param manifest     The marshalled manifest message body
 * @param digest       The output digest
 */
void AJ_ManifestDigest(AJ_CredField * manifest, uint8_t digest[SHA256_DIGEST_LENGTH]);

/**
 * Marshal a manifest record
 *
 * @param manifest     The manifest
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestMarshal(AJ_Manifest* manifest, AJ_Message* msg);

/**
 * Unmarshal a manifest record
 *
 * @param manifest     The manifest
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestUnmarshal(AJ_Manifest** manifest, AJ_Message* msg);

/**
 * Marshal a policy record
 *
 * @param policy       The policy
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyMarshal(const AJ_Policy* policy, AJ_Message* msg);

/**
 * Unmarshal a policy record
 *
 * @param policy       The policy
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyUnmarshal(AJ_Policy** policy, AJ_Message* msg);

/**
 * Free manifest memory
 *
 * @param manifest     The manifest object
 */
void AJ_ManifestFree(AJ_Manifest* manifest);

/**
 * Free policy memory
 *
 * @param policy       The policy object
 */
void AJ_PolicyFree(AJ_Policy* policy);

/**
 * Marshal the default policy
 *
 * @param msg          The outgoing message
 * @param pub          The security group CA public key
 * @param g            The security group
 * @param glen         The security group size
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_MarshalDefaultPolicy(AJ_Message* msg, AJ_ECCPublicKey* pub, uint8_t* g, size_t glen);

/**
 * Apply the manifest access rules
 *
 * @param manifest     The manifest object
 * @param name         The peer's name
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestApply(AJ_Manifest* manifest, const char* name);

/**
 * Apply the policy access rules
 *
 * @param ctx          The authentication context
 * @param name         The peer's name
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyApply(AJ_AuthenticationContext* ctx, const char* name);

/**
 * Get the policy version
 *
 * @param version      The output policy version
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyVersion(uint32_t* version);

/**
 * Access control check for message
 *
 * @param id           The message id
 * @param name         The peer's name
 * @param direction    The message direction (incoming/outgoing)
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_ACCESS on all failures
 */
AJ_Status AJ_AccessControlCheck(uint32_t id, const char* name, uint8_t direction);

/**
 * Reset access control list for a peer
 *
 * @param name         The peer's name
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_AccessControlReset(const char* name);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif
