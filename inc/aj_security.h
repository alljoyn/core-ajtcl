#ifndef _AJ_SECURITY_H
#define _AJ_SECURITY_H
/**
 * @file aj_security.h
 * @defgroup aj_security Implementation of org.alljoyn.Bus.Security.*
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

#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_crypto_sha2.h>
#include <ajtcl/aj_guid.h>
#include <ajtcl/aj_msg.h>
#include <ajtcl/aj_target.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AJ_SECURE_MGMT_PORT 101

#define APP_STATE_NOT_CLAIMABLE        0x0000
#define APP_STATE_CLAIMABLE            0x0001
#define APP_STATE_CLAIMED              0x0002
#define APP_STATE_NEED_UPDATE          0x0003

/* Authentication mechanisms supported for claiming. */
#define CLAIM_CAPABILITY_ECDHE_NULL    0x0001
#define CLAIM_CAPABILITY_ECDHE_PSK     0x0002
#define CLAIM_CAPABILITY_ECDHE_ECDSA   0x0004
#define CLAIM_CAPABILITY_ECDHE_SPEKE   0x0008

/*
 * Indicates whether the security manager or application generated the
 * pre-shared key or password used during claim.
 */
#define CLAIM_PSK_SECURITY_MANAGER     0x0001
#define CLAIM_PSK_APPLICATION          0x0002

typedef struct _AJ_CertificateId {
    DER_Element serial;                /**< Certificate serial number */
    DER_Element aki;                   /**< Certificate issuer aki */
    AJ_ECCPublicKey pub;               /**< Certificate issuer public key */
} AJ_CertificateId;

/**
 * Set the application claim configuration
 *
 * @param bus          Bus attachment
 * @param state        Claim state
 * @param capabilities Claim capabilities
 * @param info         Claim capabilities info
 *
 */
void AJ_SecuritySetClaimConfig(AJ_BusAttachment* bus, uint16_t state, uint16_t capabilities, uint16_t info);

/**
 * Get the application claim configuration
 *
 * @param state        Claim state
 * @param capabilities Claim capabilities
 * @param info         Claim capabilities info
 *
 */
void AJ_SecurityGetClaimConfig(uint16_t* state, uint16_t* capabilities, uint16_t* info);

/**
 * Initialistion for security module
 * Generates key pair if not found
 * Binds to the permission management port
 *
 * @param bus        The bus attachment
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_RESOURCES on failure
 */
AJ_Status AJ_SecurityInit(AJ_BusAttachment* bus);

/**
 * Closes security module
 * Unbinds the permission management port
 *
 * @param bus        The bus attachment
 *
 */
void AJ_SecurityClose(AJ_BusAttachment* bus);

/**
 * Send application state signal
 *
 * @param bus        The bus attachment
 *
 * @return
 *          - AJ_OK on success
 */
AJ_Status AJ_ApplicationStateSignal(AJ_BusAttachment* bus);

/**
 * Get security application property
 *
 * @param msg        The message
 *
 * @return
 *          - AJ_OK on success
 */
AJ_Status AJ_SecurityGetProperty(AJ_Message* msg);

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
 * Handle a reset message
 * Bus method handler for a MANAGED_RESET method call
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
 * Perform a security reset
 * Function called by the application to initiate a security reset
 *
 * @param bus          The bus attachment
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityReset(AJ_BusAttachment* bus);

/**
 * Handle an update identity message
 *
 * @param msg          The update identity message
 * @param reply        The update identity reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityUpdateIdentityMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle an update policy message
 *
 * @param msg          The update policy message
 * @param reply        The update policy reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityUpdatePolicyMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a reset policy message
 *
 * @param msg          The reset policy message
 * @param reply        The reset policy reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityResetPolicyMethod(AJ_Message* msg, AJ_Message* reply);

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
 * Handle a start management message
 * Bus method handler for a MANAGED_START_MANAGEMENT method call
 *
 * @param msg          The start management message
 * @param reply        The start management reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityStartManagementMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Call application's start management callback, as a result of a MANAGED_START_MANAGEMENT method call
 *
 * @param bus          The bus attachment
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_MANAGEMENT_ALREADY_STARTED on failure
 */
AJ_Status AJ_SecurityStartManagement(AJ_BusAttachment* bus);

/**
 * Handle a end management message
 * Bus method handler for a MANAGED_END_MANAGEMENT method call
 *
 * @param msg          The end management message
 * @param reply        The end management reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on all failures
 */
AJ_Status AJ_SecurityEndManagementMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Call application's end management callback, as a result of a MANAGED_END_MANAGEMENT method call
 *
 * @param bus          The bus attachment
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_MANAGEMENT_NOT_STARTED on failure
 */
AJ_Status AJ_SecurityEndManagement(AJ_BusAttachment* bus);

/**
 * Handle an install manifests message
 * Bus method handler for a MANAGED_INSTALL_MANIFESTS method call
 *
 * @param msg          The install manifests message
 * @param reply        The install manifests reply
 *
 * @return  Return AJ_Status
 *          - AJ_OK if at least one manifest is accepted and installed
 *          - AJ_ERR_SECURITY_DIGEST_MISMATCH if no manifests are accepted
 */
AJ_Status AJ_SecurityInstallManifestsMethod(AJ_Message* msg, AJ_Message* reply);

/**
 * Unmarshal an ECCPublicKey object
 *
 * @param msg          The message
 * @param pub          The ECCPublicKey object
 * @param kid          The key identifier (optional)
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_UnmarshalECCPublicKey(AJ_Message* msg, AJ_ECCPublicKey* pub, DER_Element* kid);

/**
 * Unmarshal a certificate chain field and generate the id
 *
 * @param chain        The certificate chain
 * @param id           The certificate id
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_GetCertificateId(X509CertificateChain* chain, AJ_CertificateId* id);

/**
 * Callback for the bind session port call.
 *
 * @param bus          The bus attachment
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_SecurityBound(AJ_BusAttachment* bus);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif
