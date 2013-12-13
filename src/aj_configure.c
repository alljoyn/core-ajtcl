/******************************************************************************
 * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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


#include <aj_configure.h>
#include <aj_configureme.h>


// general methods
static const char* const AllJoynConfigurationInterface[] = {
    "org.alljoyn.configure",
    "?Identify >s",
    "?MaxProfiles >u",
    "?Connect <u",
    "?ClearProfile <u",
    NULL
};

// WIFI-specific methods
static const char* const AllJoynWifiConfigurationInterface[] = {
    "org.alljoyn.configure.wifi",
    "?SetProfile index<u ssid<s password<s auth<u encryption<u",
    "?GetProfile index<u ssid>s password>s auth>u encryption>u",
    NULL
};

const AJ_InterfaceDescription AJ_ConfigInterfaces[] = {
    AllJoynConfigurationInterface,
    AllJoynWifiConfigurationInterface,
    NULL
};





#define APP_IDENTIFY    AJ_APP_MESSAGE_ID(0, 0, 0)
#define APP_MAX_PROFILE AJ_APP_MESSAGE_ID(0, 0, 1)
#define APP_CONNECT     AJ_APP_MESSAGE_ID(0, 0, 2)
#define APP_CLEAR       AJ_APP_MESSAGE_ID(0, 0, 3)

#define APP_SET_WIFI    AJ_APP_MESSAGE_ID(0, 1, 0)
#define APP_GET_WIFI    AJ_APP_MESSAGE_ID(0, 1, 1)


AJ_Status AJ_ProcessInternal(AJ_Message* msg, IdentifyFunction identifyFunction)
{
    AJ_Status status = AJ_OK;

    switch (msg->msgId) {
    case APP_SET_WIFI:
        {
            uint32_t active = AJ_GetActive();
            uint32_t index;
            char* ssid;
            char* password;
            uint32_t auth;
            uint32_t encryption;
            status = AJ_UnmarshalArgs(msg, "ussuu", &index, &ssid, &password, &auth, &encryption);

            if (status == AJ_OK) {
                status = AJ_SaveWifiProfile(index, ssid, password, auth, encryption);

                if (status == AJ_OK) {
                    AJ_Message reply;
                    AJ_MarshalReplyMsg(msg, &reply);
                    status = AJ_DeliverMsg(&reply);
                } else {
                    AJ_Message reply;
                    AJ_MarshalErrorMsg(msg, &reply, "Invalid parameter");
                    status = AJ_DeliverMsg(&reply);
                }
            }

            // if we are modifying the current profile, we need to
            if (status == AJ_OK && index == active) {
                status = AJ_ERR_RESTART;
            }

            break;
        }

    case APP_GET_WIFI:
        {
            uint32_t index;
            status = AJ_UnmarshalArgs(msg, "u", &index);

            if (status == AJ_OK) {
                const AJ_ConnectionProfile* config = AJ_ReadProfile(index);

                switch (config->type) {
                case PROFILE_TYPE_WIFI:
                    {
                        const AJ_WifiProfile* profile = &(config->wifi);
                        AJ_Message reply;
                        AJ_MarshalReplyMsg(msg, &reply);
                        AJ_MarshalArgs(&reply, "ssuu", profile->ssid, profile->password, &profile->auth, &profile->encryption);
                        status = AJ_DeliverMsg(&reply);
                        break;
                    }

                default:
                    status = AJ_ERR_INVALID;
                    break;
                }
            }

            if (status != AJ_OK) {
                AJ_Message reply;
                AJ_MarshalErrorMsg(msg, &reply, "Invalid parameter");
                status = AJ_DeliverMsg(&reply);
            }

            break;
        }

    case APP_IDENTIFY:
        {
            AJ_Message reply;
            char name[80];
            // limit the output to 80 bytes
            (*identifyFunction)(name, sizeof(name));
            name[sizeof(name) - 1] = '\0';

            AJ_MarshalReplyMsg(msg, &reply);
            AJ_MarshalArgs(&reply, "s", name);
            status = AJ_DeliverMsg(&reply);
            break;
        }

    case APP_MAX_PROFILE:
        {
            AJ_Message reply;
            uint32_t max = MAX_PROFILES;
            AJ_MarshalReplyMsg(msg, &reply);
            AJ_MarshalArgs(&reply, "u", &max);
            status = AJ_DeliverMsg(&reply);
            break;
        }

    case APP_CLEAR:
        {
            AJ_Message reply;
            uint32_t index;
            status = AJ_UnmarshalArgs(msg, "u", &index);

            if (index == AJ_GetActive()) {
                AJ_MarshalErrorMsg(msg, &reply, "Cannot clear active profile");
                status = AJ_DeliverMsg(&reply);
            } else {
                AJ_ClearConfig(index);
                AJ_MarshalReplyMsg(msg, &reply);
                status = AJ_DeliverMsg(&reply);
            }

            break;
        }

    case APP_CONNECT:
        {
            AJ_Message reply;
            uint32_t index;
            status = AJ_UnmarshalArgs(msg, "u", &index);

            if (status == AJ_OK) {
                status = AJ_SetActive(index);
                if (status == AJ_OK) {
                    AJ_MarshalReplyMsg(msg, &reply);
                    status = AJ_DeliverMsg(&reply);
                }
            }

            if (status != AJ_OK) {
                AJ_MarshalErrorMsg(msg, &reply, "Invalid parameter");
                status = AJ_DeliverMsg(&reply);
            } else {
                status = AJ_ERR_RESTART;
            }

            break;
        }

    default:
        status = AJ_ERR_UNEXPECTED;
        break;
    }

    return status;
}