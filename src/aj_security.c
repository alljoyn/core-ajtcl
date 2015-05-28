/**
 * @file
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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE SECURITY

#include "aj_config.h"
#include "aj_security.h"
#include "aj_std.h"
#include "aj_target.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgSECURITY = 0;
#endif

#define APPLICATION_VERSION                    1
#define SECURITY_APPLICATION_VERSION           1
#define SECURITY_CLAIMABLE_APPLICATION_VERSION 1
#define SECURITY_MANAGED_APPLICATION_VERSION   1

AJ_Status AJ_SecurityServerInit(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_Message msg;
    uint8_t bound = FALSE;

    AJ_InfoPrintf(("AJ_SecurityServerInit()\n"));

    /*
     * Bind to the security management port
     */
    AJ_InfoPrintf(("AJ_SecurityServerInit(): Bind Session Port %d\n", AJ_SECURE_MGMT_PORT));
    status = AJ_BusBindSessionPort(bus, AJ_SECURE_MGMT_PORT, NULL, 0);
    if (AJ_OK != status) {
        return status;
    }
    while (!bound && (AJ_OK == status)) {
        status = AJ_UnmarshalMsg(bus, &msg, AJ_UNMARSHAL_TIMEOUT);
        if (AJ_ERR_NO_MATCH == status) {
            status = AJ_OK;
            continue;
        }
        if (AJ_OK != status) {
            break;
        }
        switch (msg.msgId) {
        case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
            if (msg.hdr->msgType == AJ_MSG_ERROR) {
                AJ_ErrPrintf(("AJ_SecurityServerInit(): AJ_METHOD_BIND_SESSION_PORT: %s\n", msg.error));
                status = AJ_ERR_FAILURE;
            } else {
                AJ_InfoPrintf(("AJ_SecurityServerInit(): AJ_METHOD_BIND_SESSION_PORT: OK\n"));
                bound = TRUE;
            }
            break;

        default:
            /*
             * Pass to the built-in bus message handlers
             */
            status = AJ_BusHandleBusMessage(&msg);
            break;
        }
        AJ_CloseMsg(&msg);
    }

    return status;
}

/*
 * org.alljoyn.Bus.Application implementation
 */
static AJ_Status ApplicationGetProperty(AJ_Message* reply, uint32_t id, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;

    switch (id) {
    case AJ_PROPERTY_APPLICATION_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) APPLICATION_VERSION);
        break;

    default:
        status = AJ_ERR_UNEXPECTED;
        break;
    }

    return status;
}

AJ_Status AJ_ApplicationGetProperty(AJ_Message* msg)
{
    return AJ_BusPropGet(msg, ApplicationGetProperty, NULL);
}

AJ_Status AJ_ApplicationStateSignal(AJ_BusAttachment* bus)
{
    AJ_InfoPrintf(("AJ_ApplicationStateSignal(bus=%p)\n", bus));

    //TODO: work in progress

    return AJ_OK;
}

/*
 * org.alljoyn.Bus.Security.Application implementation
 */
static AJ_Status SecurityGetProperty(AJ_Message* reply, uint32_t id, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;

    switch (id) {
    case AJ_PROPERTY_SEC_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) SECURITY_APPLICATION_VERSION);
        break;

    case AJ_PROPERTY_SEC_APPLICATION_STATE:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_SEC_MANIFEST_DIGEST:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_SEC_ECC_PUBLICKEY:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_SEC_MANUFACTURER_CERTIFICATE:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_SEC_MANIFEST_TEMPLATE:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_SEC_CLAIM_CAPABILITIES:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_SEC_CLAIM_CAPABILITIES_INFO:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_CLAIMABLE_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) SECURITY_CLAIMABLE_APPLICATION_VERSION);
        break;

    case AJ_PROPERTY_MANAGED_VERSION:
        status = AJ_MarshalArgs(reply, "q", (uint16_t) SECURITY_MANAGED_APPLICATION_VERSION);
        break;

    case AJ_PROPERTY_MANAGED_IDENTITY:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_MANIFEST:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_IDENTITY_CERT_ID:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_POLICY_VERSION:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_POLICY:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_DEFAULT_POLICY:
        //TODO: work in progress
        break;

    case AJ_PROPERTY_MANAGED_MEMBERSHIP_SUMMARY:
        //TODO: work in progress
        break;

    default:
        status = AJ_ERR_UNEXPECTED;
        break;
    }

    return status;
}

AJ_Status AJ_SecurityGetProperty(AJ_Message* msg)
{
    return AJ_BusPropGet(msg, SecurityGetProperty, NULL);
}

/*
 * org.alljoyn.Bus.Security.ClaimableApplication implementation
 */
AJ_Status AJ_SecurityClaimMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityClaimMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

/*
 * org.alljoyn.Bus.Security.ManagedApplication implementation
 */
AJ_Status AJ_SecurityResetMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityResetMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityUpdateIdentityMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityUpdateIdentityMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityUpdatePolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityUpdatePolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityResetPolicyMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityResetPolicyMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityInstallMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityInstallMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}

AJ_Status AJ_SecurityRemoveMembershipMethod(AJ_Message* msg, AJ_Message* reply)
{
    AJ_InfoPrintf(("AJ_SecurityRemoveMembershipMethod(msg=%p, reply=%p)\n", msg, reply));

    //TODO: work in progress

    return AJ_MarshalErrorMsg(msg, reply, AJ_ErrPermissionDenied);
}
