#ifndef _AJ_SECURITY_H
#define _AJ_SECURITY_H
/**
 * @file aj_security.h
 * @defgroup aj_security Implementation of org.alljoyn.Security.PermissionMgmt
 * @{
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

#include "aj_crypto_ecc.h"
#include "aj_guid.h"
#include "aj_msg.h"
#include "aj_target.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AJ_SECURE_MGMT_PORT 101

#define AJ_TA_FMT_GUID       0

/**
 * Values for key info agility
 */
#define KEY_FMT_ALLJOYN      0
#define KEY_USE_SIG          0
#define KEY_USE_ENC          1
#define KEY_USE_DH           2
#define KEY_TYP_ECC          0
#define KEY_ALG_ECDSA_SHA256 0
#define KEY_CRV_NISTP256     0

/**
 * Key info sizes
 */
#define KEY_ECC_SZ (8 * sizeof (uint32_t))
#define KEY_ECC_PRV_SZ KEY_ECC_SZ
#define KEY_ECC_PUB_SZ (2 * KEY_ECC_SZ)
#define KEY_ECC_SEC_SZ (2 * KEY_ECC_SZ)
#define KEY_ECC_SIG_SZ (2 * KEY_ECC_SZ)
#define KEYINFO_PUB_SZ (5 + sizeof (AJ_GUID) + KEY_ECC_PUB_SZ)
#define KEYINFO_PRV_SZ (5 + sizeof (AJ_GUID) + KEY_ECC_PRV_SZ)

/**
 * We currently only support one type of key
 * This structure can be modified to support more in the future
 */
typedef struct _AJ_KeyInfo {
    uint8_t fmt;                   /**< Key format */
    uint8_t kid[sizeof (AJ_GUID)]; /**< Key identifier */
    uint8_t use;                   /**< Key usage */
    uint8_t kty;                   /**< Key type */
    uint8_t alg;                   /**< Algorithm */
    uint8_t crv;                   /**< Elliptic curve */
    union {
        ecc_privatekey privatekey;
        ecc_publickey publickey;
    } key;                         /**< Key content, either public key or private key */
} AJ_KeyInfo;

/**
 * Values for sig info agility
 */
#define SIG_FMT_ALLJOYN      0
#define SIG_ALG_ECDSA_SHA256 0
#define SIG_INFO_SZ (2 + KEY_ECC_SIG_SZ)

/*
 * We currently only support one type of signature
 * This structure can be modified to support more in the future
 */
typedef struct _AJ_SigInfo {
    uint8_t fmt;               /**< Signature format */
    uint8_t alg;               /**< Signature algorithm */
    ecc_signature signature;   /**< Signature content */
} AJ_SigInfo;

typedef enum {
    AJ_CLAIM_UNKNOWN,          /**< Application is in unknown claim state */
    AJ_CLAIM_UNCLAIMABLE,      /**< Application is currently unclaimable */
    AJ_CLAIM_CLAIMABLE,        /**< Application is currently claimable */
    AJ_CLAIM_CLAIMED           /**< Application has been claimed */
} AJ_ClaimState;

typedef enum {
    AJ_SESSION_NONE,           /**< Session is not secured */
    AJ_SESSION_ENCRYPTED,      /**< Session is encrypted but not authenticated */
    AJ_SESSION_AUTHENTICATED,  /**< Session is encrypted and authenticated */
    AJ_SESSION_AUTHORISED      /**< Session is authenticated and authorised */
} AJ_SecurityLevel;

#define AJ_ID_TYPE_ANY   0
#define AJ_ID_TYPE_PEER  1
#define AJ_ID_TYPE_GUILD 2
typedef struct _AJ_Identity {
    AJ_SecurityLevel level;    /**< Required security level for record */
    uint8_t type;              /**< Type of record */
    uint8_t* data;             /**< Peer data */
    size_t size;               /**< Peer data size */
} AJ_Identity;

typedef struct _IdRecords {
    size_t num;                /**< Number of IDs */
    AJ_Identity* id;           /**< IDs */
} IdRecords;

#define AJ_ACTION_DENIED  1
#define AJ_ACTION_PROVIDE 2
#define AJ_ACTION_CONSUME 4
#define AJ_ACTION_MODIFY  8
typedef struct _MemberRecord {
    char* mbr;                 /**< Member name */
    uint8_t typ;               /**< Member type (METHOD, SIGNAL, etc.) */
    uint8_t action;            /**< Action (PROVIDE, CONSUME, etc.) */
    uint32_t mutual;           /**< If mutual authorisation is required */
} MemberRecord;

typedef struct _RuleRecord {
    char* obj;                 /**< Object name */
    char* ifn;                 /**< Interface name */
    size_t mbrsnum;            /**< Number of members */
    MemberRecord* mbrs;        /**< Members */
} RuleRecord;

typedef struct _RuleRecords {
    size_t num;                /**< Number of rules */
    RuleRecord* rule;          /**< Rules */
} RuleRecords;

typedef struct _TermRecord {
    IdRecords ids;             /**< IDs */
    RuleRecords rules;         /**< Rules */
} TermRecord;

typedef struct _AJ_AuthRecord {
    uint8_t version;           /**< Version */
    uint32_t serial;           /**< Serial number */
    TermRecord term;           /**< Record term */
} AJ_AuthRecord;

typedef struct _AJ_Manifest {
    RuleRecords rules;         /**< Rules */
} AJ_Manifest;

/**
 * Initialistion for security module
 * Generates key pair if not found
 * Binds to the permission management port
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_RESOURCES on failure
 */
AJ_Status AJ_SecurityInit();

/**
 * Close down the security module
 * Releases the loaded policy
 */
void AJ_SecurityClose();

/**
 * Set the application to claimable or not
 *
 * @param claimable    Claim state
 *
 */
void AJ_SecuritySetClaimable(uint8_t claimable);

/**
 * Get the application's claim state
 *
 * @return the current claim state
 *
 */
AJ_ClaimState AJ_SecurityGetClaimState();

/**
 * Load the installed policy
 *
 * @param bus          The bus attachment
 *
 */
AJ_Status AJ_AuthRecordLoad(AJ_BusAttachment* bus);

/**
 * Set the in memory access policy
 *
 * @param record       The policy record
 *
 * @return
 *          - AJ_OK if the policy was set
 *          - AJ_ERR_RESOURCES if there is no space to store the policy
 */
AJ_Status AJ_AuthRecordSet(const AJ_AuthRecord* record);

/**
 * Apply the access policy for the remote peer
 *
 * @param identity     The Identity record
 * @param peer         The peer's unique name
 *
 * @return
 *          - AJ_OK if the policy was applied
 *          - AJ_ERR_RESOURCES if there was no policy for this peer
 */
AJ_Status AJ_AuthRecordApply(AJ_Identity* identity, const char* peer);

/**
 * Check the access policy for the current message
 *
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK if the message is authorised
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_AuthRecordCheck(const AJ_Message* msg);

/**
 * Marshal a policy record, sent from an administrator
 *
 * @param record       The access policy record
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_AuthRecordMarshal(const AJ_AuthRecord* record, AJ_Message* msg);

/**
 * Unmarshal a policy record, sent from an administrator
 *
 * @param record       The access policy record
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_AuthRecordUnmarshal(AJ_AuthRecord* record, AJ_Message* msg);

/**
 * Marshal the manifest record, set from the application
 *
 * @param manifest     The manifest
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestMarshal(const AJ_Manifest* manifest, AJ_Message* msg);

/**
 * Unmarshal the manifest record, sent from the application
 *
 * @param manifest     The manifest
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestUnmarshal(AJ_Manifest* manifest, AJ_Message* msg);

void AJ_ManifestFree(AJ_Manifest* manifest);
AJ_Status AJ_SecuritySetManifest(AJ_Manifest* manifest);

/**
 * Handle a claim message
 *
 * @param msg          The claim message
 * @param reply        The claim reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityClaimMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle an install policy message
 *
 * @param msg          The install policy message
 * @param reply        The install policy reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityInstallPolicyMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle an install encrypted policy message
 *
 * @param msg          The install encrypted policy message
 * @param reply        The install encrypted policy reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityInstallEncryptedPolicyMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a remove policy message
 *
 * @param msg          The remove policy message
 * @param reply        The remove policy reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityRemovePolicyMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a get policy message
 *
 * @param msg          The get policy message
 * @param reply        The get policy reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityGetPolicyMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle an install identity message
 *
 * @param msg          The install identity message
 * @param reply        The install identity reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityInstallIdentityMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a remove identity message
 *
 * @param msg          The remove identity message
 * @param reply        The remove identity reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityRemoveIdentityMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a get identity message
 *
 * @param msg          The get identity message
 * @param reply        The get identity reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityGetIdentityMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle an install membership message
 *
 * @param msg          The install membership message
 * @param reply        The install membership reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityInstallMembershipMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle an install membership authorisation data message
 *
 * @param msg          The install membership authorisation data message
 * @param reply        The install membership authorisation data reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityInstallMembershipAuthDataMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a remove membership message
 *
 * @param msg          The remove membership message
 * @param reply        The remove membership reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityRemoveMembershipMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a get manifest message
 *
 * @param msg          The get manifest message
 * @param reply        The get manifest reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityGetManifestMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a reset message
 *
 * @param msg          The reset message
 * @param reply        The reset reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityResetMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a get publickey message
 *
 * @param msg          The get publickey message
 * @param reply        The get publickey reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityGetPublicKeyMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Send a notify config signal
 *
 * @param bus          The bus attachment
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityNotifyConfig(AJ_BusAttachment* bus);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif
