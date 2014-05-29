#ifndef _AJ_AUTH_H
#define _AJ_AUTH_H
/**
 * @file aj_auth.h
 * @defgroup aj_auth Authentication
 * @{
 */
/******************************************************************************
 * Copyright (c) 2012, AllSeen Alliance. All rights reserved.
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
#include "aj_bus.h"
#include "aj_guid.h"

/**
 * Enumeration for authentication result
 */
typedef enum {
    AJ_AUTH_STATUS_SUCCESS,  /**< Indicates an authentication exchange completed succesfully */
    AJ_AUTH_STATUS_CONTINUE, /**< Indicates an authentication exchange is continuing */
    AJ_AUTH_STATUS_RETRY,    /**< Indicates an authentication failed but should be retried */
    AJ_AUTH_STATUS_FAILURE,  /**< Indicates an authentication failed fatally */
    AJ_AUTH_STATUS_ERROR     /**< Indicates an authentication challenge or response was badly formed */
} AJ_AuthResult;

/**
 * Challenge or response function for an authentication mechanism.
 *
 * @param inStr   The NUL terminated challenge or response string being input to the handler. This
 *                should be NULL on the first challenge or response.
 * @param outStr  A buffer to receive the challenger or response to send out
 * @param outLen  The length of the outStr buffer
 *
 * @return
 *         - AJ_AUTH_STATUS_SUCCESS if the authentication has completed succesfully
 *         - AJ_AUTH_STATUS_CONTINUE if the authentication is continuing
 *         - AJ_AUTH_STATUS_RETRY if the authentication failed (e.g. due to an incorrect password) but should be retried
 *         - AJ_AUTH_STATUS_FAILED if the authentication failed and should not be retried
 *         - AJ_AUTH_STATUS_ERROR if the data passed in was invalid or unexpected
 */
typedef AJ_AuthResult (*AJ_AuthAdvanceFunc)(const char* inStr, char* outStr, uint32_t outLen);

/**
 * Initializes an authentication mechanism for the specified role
 *
 * @param role     Indicates if the authentication mechanism is being initialized as a
 *                 reponder or challenger.
 * @param pwdFunc  Callback function for requesting a password.
 */
typedef AJ_Status (*AJ_AuthInitFunc)(uint8_t role, AJ_AuthPwdFunc pwdFunc);

/**
 * Finalizes the authentication mechanism storing credentials for the authenticated peer in the
 * keystore.
 *
 * @param peerGuid The guid to associate the credentials with or NULL if the
 *                 authentication was unsuccessful.
 *
 * @return
 *         - AJ_OK if the finalization completed sucesfully.
 *         - Other error status codes
 */
typedef AJ_Status (*AJ_AuthFinalFunc)(const AJ_GUID* peerGuid);

/**
 * Struct defining the interface to an authentication mechanism
 */
typedef struct _AJ_AuthMechanism {
    AJ_AuthInitFunc Init;               /**< Initialize an authentication mechnism */
    AJ_AuthAdvanceFunc Challenge;       /**< Challenge of response function for an auth mechanism */
    AJ_AuthAdvanceFunc Response;        /**< Challenge of response function for an auth mechanism */
    AJ_AuthFinalFunc Final;             /**< Finalizes the auth mechanism storing credentials */
    const char* name;                   /**< Name of authentication mechanism */
} AJ_AuthMechanism;

/**
 * Pincode authentication mechanism
 */
extern const AJ_AuthMechanism AJ_AuthPin;

/**
 * @}
 */
#endif
