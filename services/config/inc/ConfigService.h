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

#ifndef _CONFIGSERVICE_H_
#define _CONFIGSERVICE_H_

/** @defgroup ConfigService Config Service Framework
 *
 *  @{
 */

#include <ajtcl/alljoyn.h>
#include <ajtcl/services/ServicesCommon.h>

/**
 * Following definitions are read by the application.
 */

/**
 * Actions to perform when factory reset is requested.
 * Performed by the application.
 * @return status
 */
typedef AJ_Status (*AJCFG_FactoryReset)(void);

/**
 * Actions to perform when a device restart is requested.
 * Performed by the application.
 * @return aj_status
 */
typedef AJ_Status (*AJCFG_Restart)(void);

/**
 * Actions to perform when a new device passcode is set.
 * Performed by the application.
 * @param routerRealm
 * @param newPasscode
 * @param newPasscodeLen
 * @return aj_status
 */
typedef AJ_Status (*AJCFG_SetPasscode)(const char* routerRealm, const uint8_t* newPasscode, uint8_t newPasscodeLen);

/**
 * Check whether the given value is valid for the given key.
 * @param key
 * @param value
 * @return isValid
 */
typedef uint8_t (*AJCFG_IsValueValid)(const char* key, const char* value);

/**
 * Config Service API
 */

/**
 * Start Config service framework passing callbacks.
 * @param factoryReset
 * @param restart
 * @param setPasscode
 * @param isValueValid
 * @return aj_status
 */
AJ_Status AJCFG_Start(AJCFG_FactoryReset factoryReset, AJCFG_Restart restart, AJCFG_SetPasscode setPasscode, AJCFG_IsValueValid isValueValid);

/**
 * Called when Routing Node is connected.
 * @param busAttachment
 * @return aj_status
 */
AJ_Status AJCFG_ConnectedHandler(AJ_BusAttachment* busAttachment);

/**
 * Called when a new incoming message requires processing.
 * @param busAttachment
 * @param msg
 * @param msgStatus
 * @return aj_status
 */
AJSVC_ServiceStatus AJCFG_MessageProcessor(AJ_BusAttachment* busAttachment, AJ_Message* msg, AJ_Status* msgStatus);

/**
 * Called just before the Routing Node disconnects.
 * @param busAttachment
 * @return aj_status
 */
AJ_Status AJCFG_DisconnectHandler(AJ_BusAttachment* busAttachment);

/** @} */
 #endif // _CONFIGSERVICE_H_
