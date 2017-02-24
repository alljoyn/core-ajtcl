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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h.
 * The corresponding flag dbgAJSVCAPP is defined in the containing sample app.
 */
#define AJ_MODULE AJSVCAPP

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_link_timeout.h>
#include <ajtcl/services/PropertyStoreOEMProvisioning.h>
#include <ajtcl/services/ConfigService.h>
#include <ajtcl/services/PropertyStore.h>
#include <ajtcl/services/ServicesCommon.h>
#include <ajtcl/services/ServicesHandlers.h>
#include "AllJoynLogo.h"

/*
 * Logger definition
 */

#ifndef NDEBUG
#ifndef ER_DEBUG_AJSVCAPP
#define ER_DEBUG_AJSVCAPP 0
#endif
AJ_EXPORT uint8_t dbgAJSVCAPP = ER_DEBUG_AJSVCAPP;
#endif

/*
 * Define timeout/pause values. Values are in milli seconds.
 * The following may be tuned according to platform requirements such as battery usage.
 */

#define AJAPP_BUS_LINK_TIMEOUT    60
#define AJAPP_CONNECT_TIMEOUT     (1000 * 60 * 10) // Override AJ_CONNECT_TIMEOUT to wait longer for a successful connection to a Routing Node
#define AJAPP_CONNECT_PAUSE       (1000 * 2)       // Override AJ_CONNECT_PAUSE to be more responsive
#define AJAPP_SLEEP_TIME          (1000 * 2)       // A little pause to let things settle
#define AJAPP_UNMARSHAL_TIMEOUT   (1000 * 1)       // Override AJ_UNMARSHAL_TIMEOUT to be more responsive

/**
 * Application wide globals
 */

#define ROUTING_NODE_NAME "org.alljoyn.BusNode"
static uint8_t s_isBusConnected = FALSE;
static AJ_BusAttachment s_busAttachment;
#define AJ_ABOUT_SERVICE_PORT 900

/**
 * Application wide callbacks
 */

static AJ_Status AuthListenerCallback(uint32_t mechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;
    static uint8_t PASSWORD_BUFFER[UINT8_MAX];
    static const uint32_t keyexpiration = 0xFFFFFFFF;
    const char* hexPassword;
    size_t hexPasswordLen;

    memset(PASSWORD_BUFFER, 0, UINT8_MAX);

    AJ_AlwaysPrintf(("AuthListener called with mechanism %x command %x\n", mechanism, command));

    switch (mechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = keyexpiration;
        status = AJ_OK;
        break;

    case AUTH_SUITE_ECDHE_SPEKE:
        switch (command) {
        case AJ_CRED_PASSWORD:
            hexPassword = AJSVC_PropertyStore_GetValue(AJSVC_PROPERTY_STORE_PASSCODE);
            if (hexPassword != NULL) {
                hexPasswordLen = strlen(hexPassword);
                status = AJ_HexToRaw(hexPassword, hexPasswordLen, PASSWORD_BUFFER, UINT8_MAX);
                if (status == AJ_OK) {
                    cred->len = hexPasswordLen / 2;
                    cred->data = PASSWORD_BUFFER;
                    cred->expiration = keyexpiration;
                }
            } else {
                status = AJ_ERR_FAILURE;
            }
            break;
        }
        break;

    default:
        AJ_ErrPrintf(("Unsupported authentication mechanism\n"));
        break;
    }
    return status;
}

/**
 * Application handlers
 */

typedef enum {
    INIT_START = 0,
    INIT_SERVICES = INIT_START,
    INIT_SERVICES_PORT,
    INIT_ABOUT,
    INIT_CHECK_ANNOUNCE,
    INIT_FINISHED = INIT_CHECK_ANNOUNCE
} enum_init_state_t;

static enum_init_state_t currentServicesInitializationState = INIT_START;
static enum_init_state_t nextServicesInitializationState = INIT_START;

static AJ_Status AJApp_ConnectedHandler(AJ_BusAttachment* busAttachment)
{
    AJ_Status status = AJ_OK;

    if (AJ_GetUniqueName(busAttachment)) {
        if (currentServicesInitializationState == nextServicesInitializationState) {
            switch (currentServicesInitializationState) {
            case INIT_SERVICES:
                status = AJSVC_ConnectedHandler(busAttachment);
                if (status != AJ_OK) {
                    goto ErrorExit;
                }
                currentServicesInitializationState = nextServicesInitializationState = INIT_SERVICES_PORT;
                break;

            case INIT_SERVICES_PORT:
                status = AJ_BusBindSessionPort(busAttachment, AJ_ABOUT_SERVICE_PORT, NULL, 0);
                if (status != AJ_OK) {
                    goto ErrorExit;
                }
                nextServicesInitializationState = INIT_ABOUT;
                break;

            case INIT_ABOUT:
                status = AJ_AboutInit(busAttachment, AJ_ABOUT_SERVICE_PORT);
                if (status != AJ_OK) {
                    goto ErrorExit;
                }
                currentServicesInitializationState = nextServicesInitializationState = INIT_CHECK_ANNOUNCE;
                break;

            case INIT_CHECK_ANNOUNCE:
                status = AJ_AboutAnnounce(busAttachment);
                if (status != AJ_OK) {
                    goto ErrorExit;
                }
                break;

            default:
                break;
            }
        }
    }
    return status;

ErrorExit:

    AJ_ErrPrintf(("Application ConnectedHandler returned an error %s\n", (AJ_StatusText(status))));
    return status;
}

static AJSVC_ServiceStatus AJApp_MessageProcessor(AJ_BusAttachment* busAttachment, AJ_Message* msg, AJ_Status* status)
{
    AJSVC_ServiceStatus serviceStatus = AJSVC_SERVICE_STATUS_HANDLED;
    uint16_t port;
    char* joiner;
    uint32_t sessionId = 0;
    uint8_t session_accepted = FALSE;

    if (msg->msgId == AJ_METHOD_ACCEPT_SESSION) {    // Process all incoming request to join a session and pass request for acceptance by all services
        *status = AJ_UnmarshalArgs(msg, "qus", &port, &sessionId, &joiner);
        if (*status != AJ_OK) {
            return serviceStatus;
        }
        session_accepted |= (port == AJ_ABOUT_SERVICE_PORT);
        session_accepted |= AJSVC_CheckSessionAccepted(port, sessionId, joiner);
        *status = AJ_BusReplyAcceptSession(msg, session_accepted);
        AJ_AlwaysPrintf(("%s session session_id=%u joiner=%s for port %u\n", (session_accepted ? "Accepted" : "Rejected"), sessionId, joiner, port));
    } else {
        switch (currentServicesInitializationState) {
        case INIT_SERVICES_PORT:
            if (msg->msgId == AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT)) {
                currentServicesInitializationState = nextServicesInitializationState;
            }
            break;

        default:
            serviceStatus = AJSVC_MessageProcessorAndDispatcher(busAttachment, msg, status);
            break;
        }
    }

    return serviceStatus;
}

static AJ_Status AJApp_DisconnectHandler(AJ_BusAttachment* busAttachment, uint8_t restart)
{
    AJ_Status status = AJ_OK;

    if (restart) {
        AJ_BusUnbindSession(busAttachment, AJ_ABOUT_SERVICE_PORT);
    }

    AJ_AboutSetShouldAnnounce();
    currentServicesInitializationState = nextServicesInitializationState = INIT_START;

    return status;
}

/**
 * Services Provisioning
 */

const char* deviceManufactureName = "COMPANY";
const char* deviceProductName = "GENERIC BOARD";

/**
 * Config supported PropertyStore provisioning
 */

static const char DEFAULT_LANGUAGE[] = "en";
static const char* DEFAULT_LANGUAGES[] = { DEFAULT_LANGUAGE };
static const char SUPPORTED_LANG2[] = "de-AT";
static const char* SUPPORTED_LANGUAGES[] = { DEFAULT_LANGUAGE, SUPPORTED_LANG2, NULL };
const char* const* propertyStoreDefaultLanguages = SUPPORTED_LANGUAGES;

/**
 * property array of structure with defaults
 */
static const char DEFAULT_DEVICE_NAME_LANG1[] = { "Company A - \"Generic Board\"" };
static const char DEFAULT_DEVICE_NAME_LANG2[] = { "Firma A - \"Generic Board\"" };
static const char* DEFAULT_DEVICE_NAMES[] = { DEFAULT_DEVICE_NAME_LANG1, DEFAULT_DEVICE_NAME_LANG2 };
static const char* DEFAULT_PASSCODES[] = { "303030303030" }; // HEX encoded { '0', '0', '0', '0', '0', '0' }
static const char* DEFAULT_APP_NAMES[] = { "Configuree" };
static const char DEFAULT_DESCRIPTION_LANG1[] = "My First IOE device";
static const char DEFAULT_DESCRIPTION_LANG2[] = "Mein erstes IOE Geraet";
static const char* DEFAULT_DESCRIPTIONS[] = { DEFAULT_DESCRIPTION_LANG1, DEFAULT_DESCRIPTION_LANG2 };
static const char DEFAULT_MANUFACTURER_LANG1[] = "Company A(EN)";
static const char DEFAULT_MANUFACTURER_LANG2[] = "Firma A(DE-AT)";
static const char* DEFAULT_MANUFACTURERS[] = { DEFAULT_MANUFACTURER_LANG1, DEFAULT_MANUFACTURER_LANG2 };
static const char* DEFAULT_DEVICE_MODELS[] = { "0.0.1" };
static const char* DEFAULT_DATE_OF_MANUFACTURES[] = { "2014-05-01" };
static const char* DEFAULT_SOFTWARE_VERSIONS[] = { "0.0.1" };
static const char* DEFAULT_HARDWARE_VERSIONS[] = { "0.0.1" };
static const char DEFAULT_SUPPORT_URL_LANG1[] = "http://www.company_a.com";
static const char DEFAULT_SUPPORT_URL_LANG2[] = "http://www.company_a.com/de-AT";
static const char* DEFAULT_SUPPORT_URLS[] = { DEFAULT_SUPPORT_URL_LANG1, DEFAULT_SUPPORT_URL_LANG2 };

const char** propertyStoreDefaultValues[AJSVC_PROPERTY_STORE_NUMBER_OF_KEYS] =
{
// "Default Values per language",                    "Key Name"
    NULL,                                           /*DeviceId*/
    NULL,                                           /*AppId*/
    DEFAULT_DEVICE_NAMES,                           /*DeviceName*/
    DEFAULT_LANGUAGES,                              /*DefaultLanguage*/
    DEFAULT_PASSCODES,                              /*Passcode*/
    NULL,                                           /*RealmName*/
// Add other runtime keys above this line
    DEFAULT_APP_NAMES,                              /*AppName*/
    DEFAULT_DESCRIPTIONS,                           /*Description*/
    DEFAULT_MANUFACTURERS,                          /*Manufacturer*/
    DEFAULT_DEVICE_MODELS,                          /*ModelNumber*/
    DEFAULT_DATE_OF_MANUFACTURES,                   /*DateOfManufacture*/
    DEFAULT_SOFTWARE_VERSIONS,                      /*SoftwareVersion*/
    NULL,                                           /*AJSoftwareVersion*/
    NULL,                                           /*MaxLength*/
// Add other mandatory about keys above this line
    DEFAULT_HARDWARE_VERSIONS,                      /*HardwareVersion*/
    DEFAULT_SUPPORT_URLS,                           /*SupportUrl*/
// Add other optional about keys above this line
};

/**
 * properties array of runtime values' buffers
 */
static char machineIdVar[MACHINE_ID_LENGTH + 1] = { 0 };
static char* machineIdVars[] = { machineIdVar };
static char deviceNameVarLang1[DEVICE_NAME_VALUE_LENGTH + 1] = { 0 };
static char deviceNameVarLang2[DEVICE_NAME_VALUE_LENGTH + 1] = { 0 };
static char* deviceNameVars[] = { deviceNameVarLang1, deviceNameVarLang2 };
static char defaultLanguageVar[LANG_VALUE_LENGTH + 1] = { 0 };
static char* defaultLanguageVars[] = { defaultLanguageVar };
static char passcodeVar[PASSWORD_VALUE_LENGTH + 1] = { 0 };
static char* passcodeVars[] = { passcodeVar };
static char realmNameVar[KEY_VALUE_LENGTH + 1] = { 0 };
static char* realmNameVars[] = { realmNameVar };


PropertyStoreConfigEntry propertyStoreRuntimeValues[AJSVC_PROPERTY_STORE_NUMBER_OF_RUNTIME_KEYS] =
{
//  {"Buffers for Values per language", "Buffer Size"},                  "Key Name"
    { machineIdVars,             MACHINE_ID_LENGTH + 1 },               /*DeviceId*/
    { machineIdVars,             MACHINE_ID_LENGTH + 1 },               /*AppId*/
    { deviceNameVars,            DEVICE_NAME_VALUE_LENGTH + 1 },        /*DeviceName*/
    { defaultLanguageVars,       LANG_VALUE_LENGTH + 1 },               /*AppName*/
    { passcodeVars,              PASSWORD_VALUE_LENGTH + 1 },           /*Description*/
    { realmNameVars,             KEY_VALUE_LENGTH + 1 },                /*Manufacturer*/
// Add other runtime keys above this line
};

/**
 * AboutIcon Provisioning
 */
const char* aboutIconMimetype = (const char*)(AJ_LogoMimeType);
const uint8_t* aboutIconContent = AJ_LogoData;
const size_t aboutIconContentSize = AJ_LogoSize;
const char* aboutIconUrl = AJ_LogoURL;

/*
 * Config Provisioning
 */

static AJ_Status FactoryReset()
{
    AJ_Status status = AJ_OK;

    AJ_InfoPrintf(("GOT FACTORY RESET\n"));
    status = AJSVC_PropertyStore_ResetAll();
    if (status != AJ_OK) {
        return status;
    }
    AJ_ClearCredentials(0);
    return AJ_ERR_RESTART_APP;     // Force disconnect of AJ and services and reconnection of WiFi on restart of app
}

static AJ_Status Restart()
{
    AJ_InfoPrintf(("GOT RESTART REQUEST\n"));
    AJ_AboutSetShouldAnnounce(); // Set flag for sending an updated Announcement
    return AJ_ERR_RESTART_APP; // Force disconnect of AJ and services and reconnection of WiFi on restart of app
}

static AJ_Status SetPasscode(const char* daemonRealm, const uint8_t* newPasscode, uint8_t newPasscodeLen)
{
    AJ_Status status = AJ_OK;
    char newStringPasscode[PASSWORD_VALUE_LENGTH + 1];

    status = AJ_RawToHex(newPasscode, newPasscodeLen, newStringPasscode, sizeof(newStringPasscode), FALSE);
    if (status != AJ_OK) {
        return status;
    }
    if (AJSVC_PropertyStore_SetValue(AJSVC_PROPERTY_STORE_REALM_NAME, daemonRealm) && AJSVC_PropertyStore_SetValue(AJSVC_PROPERTY_STORE_PASSCODE, newStringPasscode)) {

        status = AJSVC_PropertyStore_SaveAll();
        if (status != AJ_OK) {
            return status;
        }
        AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
        status = AJ_ERR_READ;     //Force disconnect of AJ and services to refresh current sessions
    } else {

        status = AJSVC_PropertyStore_LoadAll();
        if (status != AJ_OK) {
            return status;
        }
    }

    return status;
}

static uint8_t IsValueValid(const char* key, const char* value)
{
    return TRUE;
}

static AJ_Status Config_Init()
{
    AJ_Status status = AJCFG_Start(&FactoryReset, &Restart, &SetPasscode, &IsValueValid);
    return status;
}

/**
 * The AllJoyn Message Loop
 */

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    uint8_t isUnmarshalingSuccessful = FALSE;
    AJSVC_ServiceStatus serviceStatus;
    AJ_Message msg;
    uint8_t forcedDisconnnect = FALSE;
    uint8_t rebootRequired = FALSE;

    AJ_Initialize();

    AJ_AboutSetIcon(aboutIconContent, aboutIconContentSize, aboutIconMimetype, aboutIconUrl);

    status = PropertyStore_Init();
    if (status != AJ_OK) {
        goto Exit;
    }

    status = Config_Init();
    if (status != AJ_OK) {
        goto Exit;
    }

    while (TRUE) {
        status = AJ_OK;
        serviceStatus = AJSVC_SERVICE_STATUS_NOT_HANDLED;

        if (!s_isBusConnected) {
            uint32_t suites[] = { AUTH_SUITE_ECDHE_NULL, AUTH_SUITE_ECDHE_SPEKE };
            status = AJSVC_RoutingNodeConnect(&s_busAttachment, ROUTING_NODE_NAME, AJAPP_CONNECT_TIMEOUT, AJAPP_CONNECT_PAUSE, AJAPP_BUS_LINK_TIMEOUT, &s_isBusConnected);
            if (!s_isBusConnected) { // Failed to connect to Routing Node.
                continue; // Retry establishing connection to Routing Node.
            }
            /* Setup authentication listener for secured peer to peer connections */
            AJ_BusEnableSecurity(&s_busAttachment, suites, sizeof(suites) / sizeof(*suites));
            AJ_BusSetAuthListenerCallback(&s_busAttachment, AuthListenerCallback);
        }

        status = AJApp_ConnectedHandler(&s_busAttachment);

        if (status == AJ_OK) {
            status = AJ_UnmarshalMsg(&s_busAttachment, &msg, AJAPP_UNMARSHAL_TIMEOUT);
            isUnmarshalingSuccessful = (status == AJ_OK);

            if (status == AJ_ERR_TIMEOUT) {
                if (AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(&s_busAttachment)) {
                    status = AJ_ERR_READ;             // something's not right. force disconnect
                }
            }

            if (isUnmarshalingSuccessful) {
                if (serviceStatus == AJSVC_SERVICE_STATUS_NOT_HANDLED) {
                    serviceStatus = AJApp_MessageProcessor(&s_busAttachment, &msg, &status);
                }
                if (serviceStatus == AJSVC_SERVICE_STATUS_NOT_HANDLED) {
                    //Pass to the built-in bus message handlers
                    status = AJ_BusHandleBusMessage(&msg);
                }
                AJ_NotifyLinkActive();
            }

            //Unmarshaled messages must be closed to free resources
            AJ_CloseMsg(&msg);
        }

        if (status == AJ_ERR_READ || status == AJ_ERR_WRITE || status == AJ_ERR_RESTART || status == AJ_ERR_RESTART_APP) {
            if (s_isBusConnected) {
                forcedDisconnnect = (status != AJ_ERR_READ);
                rebootRequired = (status == AJ_ERR_RESTART_APP);
                AJApp_DisconnectHandler(&s_busAttachment, forcedDisconnnect);
                AJSVC_RoutingNodeDisconnect(&s_busAttachment, forcedDisconnnect, AJAPP_SLEEP_TIME, AJAPP_SLEEP_TIME, &s_isBusConnected);
                if (rebootRequired) {
                    AJ_Reboot();
                }
            }
        }
    }     // while (TRUE)

    return 0;

Exit:

    return (1);
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif