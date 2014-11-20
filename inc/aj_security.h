#ifndef _AJ_SECURITY_H
#define _AJ_SECURITY_H
/**
 * @file aj_security.h
 * @defgroup aj_security Implementation of org.alljoyn.Security.PermissionMgmt
 * @{
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

#include "aj_crypto_ecc.h"
#include "aj_guid.h"
#include "aj_msg.h"
#include "aj_target.h"

typedef enum {
    AJ_CLAIM_UNKNOWN,          /**< Application is unknown claim state */
    AJ_CLAIM_UNCLAIMABLE,      /**< Application is currently unclaimable */
    AJ_CLAIM_CLAIMABLE,        /**< Application is currently claimable */
    AJ_CLAIM_CLAIMED,          /**< Application has been claimed */
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
typedef struct _IdRecord {
    AJ_SecurityLevel level;    /**< Required security level for record */
    uint8_t typ;               /**< Type of record */
    AJ_GUID* guid;             /**< Guild id */
} IdRecord;

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

typedef struct _TermRecord {
    size_t idsnum;             /**< Number of IDs */
    IdRecord* ids;             /**< IDs */
    size_t rulesnum;           /**< Number of rules */
    RuleRecord* rules;         /**< Rules */
} TermRecord;

typedef struct _AuthRecord {
    uint8_t version;           /**< Version */
    uint32_t serial;           /**< Serial number */
    TermRecord term;           /**< Record term */
} AuthRecord;

/**
 * Set the in memory access policy
 *
 * @param record       The policy record
 *
 * @return
 *          - AJ_OK if the policy was set
 *          - AJ_ERR_RESOURCES if there is no space to store the policy
 */
AJ_Status AJ_AuthRecordSet(const AuthRecord* record);

/**
 * Apply the access policy for the remote peer
 *
 * @param level        The security level of the session
 * @param type         The authentication type for the session
 * @param guid         The peer's guid
 * @param peer         The peer's unique name
 *
 * @return
 *          - AJ_OK if the policy was applied
 *          - AJ_ERR_RESOURCES if there was no policy for this peer
 */
AJ_Status AJ_AuthRecordApply(AJ_SecurityLevel level, uint8_t type, const AJ_GUID* guid, const char* peer);

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
 * Unmarshal a policy record, sent from an administrator
 *
 * @param record       The access policy record
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_AuthRecordUnmarshal(AuthRecord* record, AJ_Message* msg);

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
 * Send a notify config signal
 *
 * @param bus          The bus attachment
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityNotifyConfig(AJ_BusAttachment* bus);

/**
 * @}
 */
#endif
