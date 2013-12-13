/**
 * @file aj_configureme.h
 * @defgroup aj_configureme Device Configuration
 * @{
 */
/******************************************************************************
 *  * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#ifndef _AJ_CONFIGUREME_H
#define _AJ_CONFIGUREME_H

#include <aj_target.h>
#include <aj_status.h>



#define MAX_PROFILES 1              /**< NVRAM max profile */


#define PROFILE_TYPE_WIFI 1         /**< Wifi profile type */
#define SSID_LEN 32                 /**< Wifi SSID length */
#define PASS_LEN 32                 /**< Wifi pass length */

#define PROFILE_TYPE_UNDEFINED 0xFFFFFFFF       /**< Undefined profile type */

/** Structure about WifiProfile */
typedef struct {
    char ssid[SSID_LEN];            /**< Wifi SSID */
    uint32_t auth;                  /**< Wifi authentication */
    uint32_t encryption;            /**< Wifi encryption */
    uint32_t password_len;          /**< Wifi password length */
    char password[PASS_LEN];        /**< Wifi password */
} AJ_WifiProfile;


/**
 * Structure about ConnectionProfile
 */
typedef struct {
    uint32_t type;            /**< profile type */
    // this union will store other profile types for other types of networking
    union {
        AJ_WifiProfile wifi;
    };
} AJ_ConnectionProfile;


/** Configuration data from NVRAM */
typedef struct {
    uint32_t sentinel;        /**< Identified a valid, initialized credentials block */
    uint32_t active;          /**< active flag */
    char aj_password[32];     /**< string for password */
    AJ_ConnectionProfile profiles[MAX_PROFILES];    /**< connection profile */
} AJ_Configuration;


/**
 * Function pointer type for an Identify Function
 */
typedef void (*IdentifyFunction)(char*, size_t);

/**
 * Run the ConfigureMe service until the user calls Save
 *
 * @return  AJ_OK if configured
 */
AJ_Status AJ_RunConfigureMe();

/**
 * Read the configuration from NVRAM
 *
 * @return       A const pointer to the Configuration; NULL if not initialized
 */
const AJ_Configuration* AJ_GetConfiguration();

/**
 * Set the preferred connection profile
 *
 * @param index the index to set active
 *
 * @return
 *         - AJ_OK if success
 *         - AJ_ERR_UNKNOWN when index is out of range of profile is already cleared
 */
AJ_Status AJ_SetActive(uint32_t index);


/**
 * Get the active connection profile
 *
 * @return
 *          - Return active flag value of the connection profile if initialized
 *          - Return -1 if not initialized
 */
uint32_t AJ_GetActive();


/**
 * Save Wifi profile
 *
 * @param index         the index to save
 * @param ssid          ssid
 * @param password      password
 * @param auth          authentication
 * @param encryption    encryption
 *
 * @return
 *         - AJ_OK if success
 *         - AJ_ERR_INVALID when passed inappropriate arguements like
 *           ssid, password, auth, encryption, or null password
 */
AJ_Status AJ_SaveWifiProfile(uint32_t index, char* ssid, char* password, uint32_t auth, uint32_t encryption);


/**
 * Read a profile from NVRAM
 *
 * @param index  The index of the profile to read
 *
 * @return       A const pointer to the profile; NULL if not initialized
 */
const AJ_ConnectionProfile* AJ_ReadProfile(uint32_t index);


/**
 * Clears the configuration specified
 *
 * @param index  the index of the config to clear
 */
void AJ_ClearConfig(uint32_t index);

/**
 * Reset the NVRAM Configuration
 */
void AJ_ClearAll();

/**
 * Write the configuration to NVRAM
 *
 * @param config A pointer to the configuration structure
 */
void AJ_WriteConfiguration(AJ_Configuration* config);

/**
 * Initialize a configuration in NVRAM
 *
 * @return  A pointer to the configuration structure
 */
AJ_Configuration* AJ_InitializeConfig();

/**
 * @}
 */
#endif /* _AJ_CONFIGUREME_H */