/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
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
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
******************************************************************************/

#include <aj_configureme.h>
#include <aj_configure.h>

#include <alljoyn.h>
#include "aj_debug.h"

uint32_t AJ_GetActive()
{
    const AJ_Configuration* config = AJ_GetConfiguration();
    return (config ? config->active : (uint32_t) -1);
}

void AJ_ClearConfig(uint32_t index)
{
    AJ_Configuration* config = AJ_InitializeConfig();
    AJ_Configuration* old_config;

    if (index >= MAX_PROFILES || config->profiles[index].type == PROFILE_TYPE_UNDEFINED) {
        // index out of range or profile already cleared
        return;
    }

    // copy the new profile into the saved configuration
    old_config = (AJ_Configuration*) AJ_Malloc(sizeof(AJ_Configuration));
    memcpy(old_config, config, sizeof(AJ_Configuration));
    memset(&(old_config->profiles[index]), 0xFF, sizeof(AJ_ConnectionProfile));

    AJ_WriteConfiguration(old_config);
    AJ_Free(old_config);
}

AJ_Status AJ_SetActive(uint32_t index)
{
    AJ_Configuration* config = AJ_InitializeConfig();
    AJ_Configuration* old_config;

    if (index >= MAX_PROFILES || config->profiles[index].type == PROFILE_TYPE_UNDEFINED) {
        // index out of range or profile already cleared
        return AJ_ERR_UNKNOWN;
    }

    old_config = (AJ_Configuration*) AJ_Malloc(sizeof(AJ_Configuration));
    memcpy(old_config, config, sizeof(AJ_Configuration));

    AJ_Printf("Setting active index %u\n", index);
    old_config->active = index;
    AJ_WriteConfiguration(old_config);
    AJ_Free(old_config);
    return AJ_OK;
}

const AJ_ConnectionProfile* AJ_ReadProfile(uint32_t index)
{
    AJ_Configuration* config = AJ_InitializeConfig();
    AJ_ConnectionProfile* profile = NULL;
    AJ_Printf("AJ_ReadConfig\n");

    if (index < MAX_PROFILES && config->profiles[index].type != PROFILE_TYPE_UNDEFINED) {
        profile = &(config->profiles[index]);
    }

#ifndef NDEBUG
    AJ_Printf("Config:\n");
    AJ_DumpBytes(NULL, (const uint8_t*)config,  sizeof(AJ_Configuration));

    AJ_Printf("Profile:\n");
    AJ_DumpBytes(NULL, (const uint8_t*)profile,  sizeof(AJ_ConnectionProfile));
#endif

    return profile;
}

void AJ_SavePassword(char* password)
{
    AJ_Configuration* config = AJ_InitializeConfig();
    AJ_Configuration* old_config;

    AJ_Printf("Setting password to %s\n", password);
    old_config = (AJ_Configuration*) AJ_Malloc(sizeof(AJ_Configuration));
    memcpy(old_config, config, sizeof(AJ_Configuration));
    strcpy(old_config->aj_password, password);

    AJ_WriteConfiguration(old_config);
    AJ_Free(old_config);
}


void AJ_StoreConfig(uint32_t index, char* ssid, char* password, uint32_t auth, uint32_t encryption)
{
    AJ_Configuration* config = AJ_InitializeConfig();
    AJ_Configuration* old_config;
    AJ_ConnectionProfile* config_profile = NULL;
    AJ_WifiProfile* wifi = NULL;

    if (index >= MAX_PROFILES) {
        return;
    }

    AJ_Printf("Storing WIFI Profile [%u]: ssid=[%s], pass=[%s], auth=[%u], encryption=[%u]\n",
              index, ssid, password, auth, encryption);

    // copy config and overwrite the profile
    old_config = (AJ_Configuration*) AJ_Malloc(sizeof(AJ_Configuration));
    memcpy(old_config, config, sizeof(AJ_Configuration));

    // get the config profile and the wifi profile
    config_profile = &(old_config->profiles[index]);
    config_profile->type = PROFILE_TYPE_WIFI;

    // get the wifi profile out of the config union
    wifi = &(config_profile->wifi);

    strcpy(wifi->ssid, ssid);
    strcpy(wifi->password, password);
    wifi->auth = auth;
    wifi->encryption = encryption;

    AJ_WriteConfiguration(old_config);

#ifndef NDEBUG
    AJ_Printf("AJ_StoreConfig:\n");
    AJ_DumpBytes(NULL, (const uint8_t*)config,  sizeof(AJ_Configuration));
#endif

    AJ_Free(old_config);
}




// **************************************************************************************
// **************************************************************************************
// *******************************  QUICKJOYN INTERFACE *********************************
// **************************************************************************************
// **************************************************************************************

AJ_Status AJ_SaveWifiProfile(uint32_t index, char* ssid, char* password, uint32_t auth, uint32_t encryption)
{
    if (strlen(ssid) >= SSID_LEN) {
        return AJ_ERR_INVALID;
    }

    if (strlen(password) >= PASS_LEN) {
        return AJ_ERR_INVALID;
    }

    if (auth > 3) {
        return AJ_ERR_INVALID;
    }

    if (encryption > 2) {
        return AJ_ERR_INVALID;
    }

    // security with no password
    if (auth && *password == '\0') {
        return AJ_ERR_INVALID;
    }


    AJ_StoreConfig(index, ssid, password, auth, encryption);
    return AJ_OK;
}



static const char ServiceName[] = "org.alljoyn.configureme";
static const uint16_t ServicePort = 24;

static const char* const initialWifiConfigInterface[] = {
    "org.alljoyn.quickjoyn.wifi",
    "?Save ssid<s password<s auth<u encryption<u",
    NULL
};

static const char* const initialConfigInterface[] = {
    "org.alljoyn.quickjoyn",
    "?SetPassword password<s",
    "?Identify >s",
    NULL
};


static const AJ_InterfaceDescription interfaces[] = {
    initialConfigInterface,
    initialWifiConfigInterface,
    NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object AppObjects[] = {
    { "/org/alljoyn/quickjoyn", interfaces },
    { NULL }
};

/*
 * Message identifiers for the method calls lthis application implements
 */

#define APP_SET_PASS        AJ_APP_MESSAGE_ID(0, 0, 0)
#define APP_IDENTIFY        AJ_APP_MESSAGE_ID(0, 0, 1)
#define APP_SAVE            AJ_APP_MESSAGE_ID(0, 1, 0)

#define CONNECT_TIMEOUT    (1000 * 60)
#define UNMARSHAL_TIMEOUT  (1000 * 5)

static AJ_Status AppSaveState(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    char* ssid;
    char* password;
    uint32_t auth;
    uint32_t encryption;

    AJ_Printf("AppSaveState\n");
    status = AJ_UnmarshalArgs(msg, "ssuu", &ssid, &password, &auth, &encryption);

    if (status == AJ_OK) {
        status = AJ_SaveWifiProfile(0, ssid, password, auth, encryption);
    } else {
        AJ_Printf("Unmarshall returned %d\n", status);
    }

    return status;
}

static AJ_Status AppSavePassword(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    char* password;
    status = AJ_UnmarshalArgs(msg, "s", &password);
    if (status == AJ_OK) {
        AJ_SavePassword(password);
    }

    return status;
}


AJ_Status AJ_RunConfigureMe()
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t configured = FALSE;
    uint8_t connected = FALSE;

    // char* name
    IdentifyFunction identifyFunction = NULL;

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);


    while (!configured) {
        AJ_Message msg;

        if (connected == FALSE) {
            AJ_Printf("Calling AJ_StartService\n");
            status = AJ_StartService(&bus,
                                     "org.alljoyn",
                                     CONNECT_TIMEOUT,
                                     ServicePort,
                                     ServiceName,
                                     AJ_NAME_REQ_DO_NOT_QUEUE,
                                     NULL);

            if (status != AJ_OK) {
                AJ_Printf("AJ_StartService returned %d\n", status);
                continue;
            }
            AJ_Printf("StartService started\n");
            connected = TRUE;
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            AJ_Sleep(100);
            continue;
        }

        if (status == AJ_OK) {
            switch (msg.msgId) {
            case AJ_SIGNAL_SESSION_JOINED:
            case AJ_SIGNAL_NAME_ACQUIRED:
                break;

            case AJ_METHOD_ACCEPT_SESSION:
                status = AJ_BusReplyAcceptSession(&msg, TRUE);
                break;

            case APP_SAVE:
                status = AppSaveState(&msg);
                if (status == AJ_OK) {
                    AJ_Message reply;
                    configured = 1;
                    AJ_MarshalReplyMsg(&msg, &reply);
                    status = AJ_DeliverMsg(&reply);
                } else {
                    AJ_Message reply;
                    AJ_MarshalErrorMsg(&msg, &reply, "Invalid parameter");
                    status = AJ_DeliverMsg(&reply);
                }
                break;

            case APP_SET_PASS:
                status = AppSavePassword(&msg);
                break;

            case APP_IDENTIFY:
                {
                    AJ_Message reply;
                    char name[80];
                    name[0] = '\0';
                    if (identifyFunction != NULL) {
                        (*identifyFunction)(name, sizeof(name));
                        // DO NOT allow more than 80 bytes
                        name[sizeof(name) - 1] = '\0';
                    }
                    AJ_MarshalReplyMsg(&msg, &reply);
                    AJ_MarshalArgs(&reply, "s", name);
                    status = AJ_DeliverMsg(&reply);
                    break;
                }

            case AJ_SIGNAL_SESSION_LOST:
                connected = FALSE;
                break;

            default:
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }


        AJ_CloseMsg(&msg);

        if (status == AJ_ERR_READ) {
            AJ_Printf("AllJoyn disconnect\n");
            AJ_Disconnect(&bus);
            //AJ_ReadConfig(config);
            connected = FALSE;
            break;
        }
    }

    AJ_Printf("AJ_RunConfigureMe: finished %d\n", status);
    AJ_Disconnect(&bus);
    return status;
}