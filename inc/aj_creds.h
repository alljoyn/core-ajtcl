#ifndef _AJ_CREDS_H
#define _AJ_CREDS_H

/**
 * @file aj_creds.h
 * @defgroup aj_creds Credentials Management
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

#include "aj_target.h"
#include "aj_guid.h"
#include "aj_status.h"
#include "aj_config.h"
#include "aj_crypto_ecc.h"
#include "aj_crypto_sha2.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type low byte is basic type
 */
#define AJ_CRED_TYPE_GENERIC        0x0001 /**< generic type */
#define AJ_CRED_TYPE_AES            0x0002 /**< AES type */
#define AJ_CRED_TYPE_PRIVATE        0x0003 /**< private key type */
#define AJ_CRED_TYPE_PEM            0x0004 /**< PEM encoded type */
#define AJ_CRED_TYPE_PUBLIC         0x0005 /**< public key type */
#define AJ_CRED_TYPE_CERTIFICATE    0x0006 /**< Certificate type */
#define AJ_CRED_TYPE_KEYINFO        0x0007 /**< keyinfo type */
#define AJ_CRED_TYPE_POLICY         0x0008 /**< policy type */

/**
 * Type high byte is basic type (low byte) context specific
 */
#define AJ_KEYINFO_ECDSA_CA_PUB     0x0100 /**< Certificate signing public key */
#define AJ_KEYINFO_ECDSA_CA_PRV     0x0200 /**< Certificate signing private key */
#define AJ_KEYINFO_ECDSA_SIG_PUB    0x0300 /**< Communication public key */
#define AJ_KEYINFO_ECDSA_SIG_PRV    0x0400 /**< Communication private key */
#define AJ_CERTIFICATE_IDN_X509_DER 0x0100 /**< DER encoded identity certificate */
#define AJ_CERTIFICATE_MBR_X509_DER 0x0200 /**< DER encoded membership certificate */
#define AJ_POLICY_LOCAL             0x0100 /**< Installed local policy */
#define AJ_POLICY_MEMBERSHIP        0x0200 /**< Membership authorisation data */

/**
 * Credential storage structures
 */
typedef struct _AJ_CredField {
    uint16_t size;             /**< Field size */
    uint8_t* data;             /**< Field data */
} AJ_CredField;

/**
 * Type + id is a unique key for the credential store
 */
typedef struct _AJ_CredHead {
    uint16_t type;             /**< Credential type */
    AJ_CredField id;           /**< Credential ID, length 1 */
} AJ_CredHead;

typedef struct _AJ_CredBody {
    uint32_t expiration;       /**< Expiry time expressed a number of seconds since Epoch */
    AJ_CredField association;  /**< Credential Association, length 1 */
    AJ_CredField data;         /**< Credential Data, length 2 */
} AJ_CredBody;

typedef struct _AJ_Cred {
    AJ_CredHead head;          /**< Credential head */
    AJ_CredBody body;          /**< Credential body */
} AJ_Cred;

/**
 * Write a peer credential to NVRAM
 *
 * @param cred         The credential to store
 *
 * @return
 *          - AJ_OK if the credentials were written
 *          - AJ_ERR_RESOURCES if there is no space to write the credentials
 */
AJ_Status AJ_StoreCredential(AJ_Cred* cred);

/**
 * Store the peer secret
 *
 * @param guid         The peer's GUID
 * @param secret       The peer's secret
 * @param len          The peer's secret's length
 * @param expiration   The expiration of the secret
 *
 * @return
 *          - AJ_OK if the credentials were written
 *          - AJ_ERR_RESOURCES if there is no space to write the credentials
 */
AJ_Status AJ_StorePeerSecret(const AJ_GUID* guid, const uint8_t* secret, uint8_t len, uint32_t expiration);

/**
 * Delete a peer credential from NVRAM
 *
 * @param guid         The guid for the peer that has credentials to delete
 *
 * @return
 *          - AJ_OK if the credentials were deleted
 */
AJ_Status AJ_DeletePeerCredential(const AJ_GUID* guid);

/**
 * Clears all peer credentials
 *
 * @param type         The type of credentials to clear (0 for all).
 *
 * @return
 *          - AJ_OK if all credentials have been deleted
 */
AJ_Status AJ_ClearCredentials(uint16_t type);

/**
 * Get the credentials for a specific remote peer from NVRAM.
 *
 * @param guid         The input GUID for the remote peer
 * @param cred         The output credential
 *
 * @return
 *      - AJ_OK if the credentials for the specific remote peer exist and are copied into the buffer
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_GetPeerCredential(const AJ_GUID* guid, AJ_Cred* cred);

/**
 * Free the memory allocation for this credential object
 *
 * @param cred         Pointer to a credential object
 *
 */
void AJ_CredFree(AJ_Cred* cred);

/**
 * Free the memory allocation for this credential head object
 *
 * @param head         Pointer to a credential head object
 *
 */
void AJ_CredHeadFree(AJ_CredHead* head);

/**
 * Free the memory allocation for this credential body object
 *
 * @param body         Pointer to a credential body object
 *
 */
void AJ_CredBodyFree(AJ_CredBody* body);

/**
 * Delete a credential from NVRAM
 *
 * @param head         Pointer to a credential head object
 *
 * @return
 *          - AJ_OK if the credentials were deleted
 */
AJ_Status AJ_DeleteCredential(const AJ_CredHead* head);

/**
 * Get the credentials for a specific id from NVRAM
 *
 * @param head         Pointer to a credential head object
 * @param body         Pointer to a credential body object
 *
 * @return
 *      - AJ_OK if the credential is found
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_GetCredential(const AJ_CredHead* head, AJ_CredBody* body);

/**
 * Get the credentials for a specific id from NVRAM, starting from a given slot
 *
 * @param head         Pointer to a credential head object
 * @param body         Pointer to a credential body object
 * @param slot         Starting slot number
 *
 * @return
 *      - AJ_OK if the credential is found
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_GetNextCredential(const AJ_CredHead* head, AJ_CredBody* body, uint16_t* slot);

/**
 * Store a local credential
 *
 * @param type         The credential type
 * @param id           The local id
 * @param data         The data
 * @param len          The data length
 * @param expiration   The expiration of the data
 *
 * @return
 *          - AJ_OK if the credentials were written
 *          - AJ_ERR_RESOURCES if there is no space to write the credentials
 */
AJ_Status AJ_StoreLocalCredential(const uint16_t type, const uint16_t id, const uint8_t* data, const uint8_t len, uint32_t expiration);

/**
 * Delete the local credentials for a specific id from NVRAM
 *
 * @param type         The credential type to delete
 * @param id           The credential id to delete
 *
 * @return
 *      - AJ_OK if the credential is deleted
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_DeleteLocalCredential(const uint16_t type, const uint16_t id);

/**
 * Checks a credential's expiry
 *
 * @param cred         The credential
 *
 * @return
 *      - AJ_OK if the credential has not expired
 *      - AJ_ERR_KEY_EXPIRED if the credential has expired
 *      - AJ_ERR_INVALID if not clock is available
 */
AJ_Status AJ_CredentialExpired(AJ_Cred* cred);

/**
 * Get the GUID for this peer
 * If this is the first time the GUID has been requested this function,
 * it will generate the GUID and store it in NVRAM
 *
 * @param guid         Pointer to a buffer that has enough space to store the local GUID
 *
 * @return - AJ_OK on success
 *         - AJ_ERR_FAILURE on failure
 */
AJ_Status AJ_GetLocalGUID(AJ_GUID* guid);

/**
 * Set the GUID for this peer
 *
 * @param guid         Pointer to guid buffer to store
 *
 * @return - AJ_OK on success
 *         - AJ_ERR_FAILURE on failure
 */
AJ_Status AJ_SetLocalGUID(AJ_GUID* guid);

/**
 * Read credential from a given slot
 *
 * @param cred         The output credential
 * @param slot         The slot to read from
 *
 * @return - AJ_OK on success
 *         - AJ_ERR_FAILURE on failure
 */
AJ_Status AJ_ReadCredential(AJ_Cred* cred, uint16_t slot);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
