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

#include "aj_creds.h"
#include "aj_crypto_ecc.h"
#include "aj_crypto_sha2.h"
#include "aj_guid.h"
#include "aj_msg.h"
#include "aj_target.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AJ_SECURE_MGMT_PORT 101

#define APP_STATE_NOT_CLAIMABLE        0x0000
#define APP_STATE_CLAIMABLE            0x0001
#define APP_STATE_CLAIMED              0x0002
#define APP_STATE_NEED_UPDATE          0x0003

#define CLAIM_CAPABILITY_ECDHE_NULL    0x0001
#define CLAIM_CAPABILITY_ECDHE_PSK     0x0002
#define CLAIM_CAPABILITY_ECDHE_ECDSA   0x0004
#define CLAIM_PSK_SECURITY_MANAGER     0x0001
#define CLAIM_PSK_APPLICATION          0x0002

/**
 * Set the application claim configuration
 *
 * @param state        Claim state
 * @param capabilities Claim capabilities
 * @param info         Claim capabilities info
 *
 */
void AJ_SecuritySetClaimConfig(uint16_t state, uint16_t capabilities, uint16_t info);

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
 * Get application property
 *
 * @param msg        The message
 *
 * @return
 *          - AJ_OK on success
 */
AJ_Status AJ_ApplicationGetProperty(AJ_Message* msg);

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
 * Unmarshal an ECCPublicKey object
 *
 * @param msg          The message
 * @param pub          The ECCPublicKey object
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID on all failures
 */
AJ_Status AJ_UnmarshalECCPublicKey(AJ_Message* msg, AJ_ECCPublicKey* pub);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif
