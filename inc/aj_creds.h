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

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_guid.h>
#include <ajtcl/aj_status.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_crypto_ecc.h>

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
#define AJ_CRED_TYPE_MANIFESTS      0x0007 /**< manifests type */
#define AJ_CRED_TYPE_POLICY         0x0008 /**< policy type */
#define AJ_CRED_TYPE_CONFIG         0x0009 /**< config type */

/**
 * Type high byte is basic type (low byte) context specific
 */
#define AJ_GENERIC_MASTER_SECRET    0x0000 /**< Peer master secret */
#define AJ_GENERIC_ECDSA_THUMBPRINT 0x0100 /**< Identity certificate thumbprint from ECDSA authentication */
#define AJ_GENERIC_ECDSA_KEYS       0x0200 /**< Public keys from ECDSA authentication */
#define AJ_ECC_SIG                  0x0000 /**< ECC key for communication */
#define AJ_CERTIFICATE_OEM_X509     0x0000 /**< Manufacturer certificate */
#define AJ_CERTIFICATE_IDN_X509     0x0100 /**< AllJoyn identity certificate */
#define AJ_CERTIFICATE_MBR_X509     0x0200 /**< AllJoyn membership certificate */
#define AJ_CERTIFICATE_UNR_X509     (AJ_CERTIFICATE_IDN_X509 | AJ_CERTIFICATE_MBR_X509) /**< Unrestricted AllJoyn certificate */
#define AJ_CERTIFICATE_INV_X509     0x0400 /**< Invalid certificate (EKUs present but no AllJoyn EKUs) */
#define AJ_POLICY_DEFAULT           0x0000 /**< Default policy */
#define AJ_POLICY_INSTALLED         0x0100 /**< Installed policy */
#define AJ_CONFIG_CLAIMSTATE        0x0000 /**< Claim state */
#define AJ_CONFIG_ADMIN_GROUP       0x0100 /**< Admin group identifier */

/**
 * Credential storage structures
 */
typedef struct _AJ_CredField {
    uint16_t size;             /**< Field size */
    uint8_t* data;             /**< Field data */
} AJ_CredField;

/**
 * Read the credential from an NVRAM slot
 *
 * @param type         Credential type
 * @param id           Credential id
 * @param expiration   Credential expiration
 * @param data         Credential data
 * @param slot         NVRAM slot
 *
 * @return
 *      - AJ_OK if the credential is found
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_CredentialRead(uint16_t* type, AJ_CredField* id, uint32_t* expiration, AJ_CredField* data, uint16_t slot);

/**
 * Set the credential for a (type, id) pair
 *
 * @param type         Credential type
 * @param id           Credential id
 * @param expiration   Credential expiration
 * @param data         Credential data
 *
 * @return
 *      - AJ_OK if the credential is found
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_CredentialSet(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_CredField* data);

/**
 * Get the credential for a (type, id) pair
 *
 * @param type         Credential type
 * @param id           Credential id
 * @param expiration   Credential expiration
 * @param data         Credential data
 *
 * @return
 *      - AJ_OK if the credential is found
 *      - AJ_ERR_UNKNOWN otherwise
 */
AJ_Status AJ_CredentialGet(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_CredField* data);

/**
 * Get the credential for a (type, id) pair starting from a given slot
 *
 * @param type         Credential type
 * @param id           Credential id
 * @param expiration   Credential expiration
 * @param data         Credential data
 * @param slot         NVRAM slot to start searching from
 *
 * @return
 *      - AJ_OK if the credential is found
 *      - AJ_ERR_UNKNOWN otherwise
 */
AJ_Status AJ_CredentialGetNext(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_CredField* data, uint16_t* slot);

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
 * Set the credential for a peer
 *
 * @param type         The credential type
 * @param guid         The peer's GUID
 * @param expiration   The credential expiration
 * @param secret       The credential secret
 * @param size         The credential secret size
 *
 * @return
 *          - AJ_OK if the credentials were written
 *          - AJ_ERR_RESOURCES if there is no space to write the credentials
 */
AJ_Status AJ_CredentialSetPeer(uint16_t type, const AJ_GUID* guid, uint32_t expiration, const uint8_t* secret, uint16_t size);

/**
 * Get the credential for a peer
 *
 * @param type         The credential type
 * @param guid         The input GUID for the remote peer
 * @param expiration   The credential expiration
 * @param data         The credential data
 *
 * @return
 *      - AJ_OK if the credentials for the specific remote peer exist and are copied into the buffer
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_CredentialGetPeer(uint16_t type, const AJ_GUID* guid, uint32_t* expiration, AJ_CredField* data);

/**
 * Set the credential for an ECC public key
 *
 * @param type         The credential type
 * @param id           The credential id
 * @param expiration   The credential expiration
 * @param pub          The ECC public key
 *
 * @return
 *      - AJ_OK on success
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_CredentialSetECCPublicKey(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_ECCPublicKey* pub);

/**
 * Get the credential for an ECC public key
 *
 * @param type         The credential type
 * @param id           The credential id
 * @param expiration   The credential expiration
 * @param pub          The ECC public key
 *
 * @return
 *      - AJ_OK on success
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_CredentialGetECCPublicKey(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_ECCPublicKey* pub);

/**
 * Set the credential for an ECC private key
 *
 * @param type         The credential type
 * @param id           The credential id
 * @param expiration   The credential expiration
 * @param prv          The ECC private key
 *
 * @return
 *      - AJ_OK on success
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_CredentialSetECCPrivateKey(uint16_t type, const AJ_CredField* id, uint32_t expiration, const AJ_ECCPrivateKey* prv);

/**
 * Get the credential for an ECC private key
 *
 * @param type         The credential type
 * @param id           The credential id
 * @param expiration   The credential expiration
 * @param prv          The ECC private key
 *
 * @return
 *      - AJ_OK on success
 *      - AJ_ERR_FAILURE otherwise
 */
AJ_Status AJ_CredentialGetECCPrivateKey(uint16_t type, const AJ_CredField* id, uint32_t* expiration, AJ_ECCPrivateKey* prv);

/**
 * Delete a credential from a specified slot in NVRAM
 *
 * @param type         Credential type
 * @param slot         NVRAM slot
 *
 * @return
 *          - AJ_OK if the credentials were deleted
 */
AJ_Status AJ_CredentialDeleteSlot(uint16_t type, uint16_t slot);

/**
 * Delete a credential from NVRAM
 *
 * @param type         Credential type
 * @param id           Credential id
 *
 * @return
 *          - AJ_OK if the credentials were deleted
 */
AJ_Status AJ_CredentialDelete(uint16_t type, const AJ_CredField* id);

/**
 * Delete a peer credential from NVRAM
 *
 * @param type         The credential type
 */
void AJ_CredentialDeletePeer(const AJ_GUID* guid);

/**
 * Clears credentials
 *
 * @param type         The type of credentials to clear (0 for all).
 *
 * @return
 *          - AJ_OK if all credentials have been deleted
 */
AJ_Status AJ_ClearCredentials(uint16_t type);

/**
 * Free the memory allocation for this credential field
 *
 * @param field       Pointer to a credential field
 *
 */
void AJ_CredFieldFree(AJ_CredField* field);

/**
 * Checks a credential's expiry
 *
 * @param expiration   The credential expiration
 *
 * @return
 *      - AJ_OK if the credential has not expired
 *      - AJ_ERR_KEY_EXPIRED if the credential has expired
 *      - AJ_ERR_INVALID if not clock is available
 */
AJ_Status AJ_CredentialExpired(uint32_t expiration);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
