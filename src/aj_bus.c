/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012,2013, AllSeen Alliance. All rights reserved.
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
#include "aj_msg.h"
#include "aj_bufio.h"
#include "aj_bus.h"
#include "aj_util.h"
#include "aj_creds.h"
#include "aj_std.h"
#include "aj_introspect.h"
#include "aj_peer.h"


/**
 * Timeout for the method calls in this module
 */
#define TIMEOUT  (1000* 3)

const char* AJ_GetUniqueName(AJ_BusAttachment* bus)
{
    return (*bus->uniqueName) ? bus->uniqueName : NULL;
}

AJ_Status AJ_BusRequestName(AJ_BusAttachment* bus, const char* name, uint32_t flags)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_REQUEST_NAME, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "su", name, flags);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusReleaseName(AJ_BusAttachment* bus, const char* name)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_RELEASE_NAME, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", name);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusAdvertiseName(AJ_BusAttachment* bus, const char* name, uint16_t transportMask, uint8_t op)
{
    AJ_Status status;
    AJ_Message msg;
    uint32_t msgId = (op == AJ_BUS_START_ADVERTISING) ? AJ_METHOD_ADVERTISE_NAME : AJ_METHOD_CANCEL_ADVERTISE;

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "sq", name, transportMask);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusFindAdvertisedName(AJ_BusAttachment* bus, const char* namePrefix, uint8_t op)
{
    AJ_Status status;
    AJ_Message msg;
    uint32_t msgId = (op == AJ_BUS_START_FINDING) ? AJ_METHOD_FIND_NAME : AJ_METHOD_CANCEL_FIND_NAME;

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", namePrefix);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusFindAdvertisedNameByTransport(AJ_BusAttachment* bus, const char* namePrefix, uint16_t transpsort, uint8_t op)
{
    AJ_Status status;
    AJ_Message msg;
    uint32_t msgId = (op == AJ_BUS_START_FINDING) ? AJ_METHOD_FIND_NAME_BY_TRANSPORT : AJ_METHOD_CANCEL_FIND_NAME_BY_TRANSPORT;

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "sq", namePrefix, transpsort);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

static AJ_Status MarshalSessionOpts(AJ_Message* msg, const AJ_SessionOpts* opts)
{
    AJ_Arg dictionary;

    AJ_MarshalContainer(msg, &dictionary, AJ_ARG_ARRAY);

    AJ_MarshalArgs(msg, "{sv}", "traf",  "y", opts->traffic);
    AJ_MarshalArgs(msg, "{sv}", "multi", "b", opts->isMultipoint);
    AJ_MarshalArgs(msg, "{sv}", "prox",  "y", opts->proximity);
    AJ_MarshalArgs(msg, "{sv}", "trans", "q", opts->transports);

    AJ_MarshalCloseContainer(msg, &dictionary);

    return AJ_OK;
}

/*
 * Default session options
 */
static const AJ_SessionOpts defaultSessionOpts = {
    AJ_SESSION_TRAFFIC_MESSAGES,
    AJ_SESSION_PROXIMITY_ANY,
    AJ_TRANSPORT_ANY,
    FALSE
};

AJ_Status AJ_BusBindSessionPort(AJ_BusAttachment* bus, uint16_t port, const AJ_SessionOpts* opts)
{
    AJ_Status status;
    AJ_Message msg;

    if (!opts) {
        opts = &defaultSessionOpts;
    }
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_BIND_SESSION_PORT, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "q", port);
        status = MarshalSessionOpts(&msg, opts);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusUnbindSession(AJ_BusAttachment* bus, uint16_t port)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_UNBIND_SESSION, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "q", port);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusCancelSessionless(AJ_BusAttachment* bus, uint32_t serialNum)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_CANCEL_SESSIONLESS, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "u", serialNum);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusJoinSession(AJ_BusAttachment* bus, const char* sessionHost, uint16_t port, const AJ_SessionOpts* opts)
{
    AJ_Status status;
    AJ_Message msg;

    if (!opts) {
        opts = &defaultSessionOpts;
    }
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_JOIN_SESSION, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "sq", sessionHost, port);

        if (status == AJ_OK) {
            status = MarshalSessionOpts(&msg, opts);
        }
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusLeaveSession(AJ_BusAttachment* bus, uint32_t sessionId)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_LEAVE_SESSION, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "u", sessionId);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusSetLinkTimeout(AJ_BusAttachment* bus, uint32_t sessionId, uint32_t linkTimeout)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SET_LINK_TIMEOUT, AJ_BusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        (void)AJ_MarshalArgs(&msg, "u", sessionId);
        (void)AJ_MarshalArgs(&msg, "u", linkTimeout);
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusSetSignalRule(AJ_BusAttachment* bus, const char* ruleString, uint8_t rule)
{
    AJ_Status status;
    AJ_Message msg;
    uint32_t msgId = (rule == AJ_BUS_SIGNAL_ALLOW) ? AJ_METHOD_ADD_MATCH : AJ_METHOD_REMOVE_MATCH;

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_DBusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        uint32_t sz = 0;
        uint8_t nul = 0;
        sz = (uint32_t)strlen(ruleString);
        status = AJ_DeliverMsgPartial(&msg, sz + 5);
        AJ_MarshalRaw(&msg, &sz, 4);
        AJ_MarshalRaw(&msg, ruleString, strlen(ruleString));
        AJ_MarshalRaw(&msg, &nul, 1);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusSetSignalRule2(AJ_BusAttachment* bus, const char* signalName, const char* interfaceName, uint8_t rule)
{
    AJ_Status status;
    AJ_Message msg;
    const char* str[5];
    uint32_t msgId = (rule == AJ_BUS_SIGNAL_ALLOW) ? AJ_METHOD_ADD_MATCH : AJ_METHOD_REMOVE_MATCH;

    str[0] = "type='signal',member='";
    str[1] = signalName;
    str[2] = "'interface='";
    str[3] = interfaceName;
    str[4] = "'";

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_DBusDestination, 0, 0, TIMEOUT);
    if (status == AJ_OK) {
        size_t i;
        uint32_t sz = 0;
        uint8_t nul = 0;
        for (i = 0; i < ArraySize(str); ++i) {
            sz += (uint32_t)strlen(str[i]);
        }
        status = AJ_DeliverMsgPartial(&msg, sz + 5);
        AJ_MarshalRaw(&msg, &sz, 4);
        for (i = 0; i < ArraySize(str); ++i) {
            AJ_MarshalRaw(&msg, str[i], strlen(str[i]));
        }
        AJ_MarshalRaw(&msg, &nul, 1);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusReplyAcceptSession(AJ_Message* msg, uint32_t accept)
{
    AJ_Message reply;

    AJ_MarshalReplyMsg(msg, &reply);
    AJ_MarshalArgs(&reply, "b", accept);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status HandleGetMachineId(AJ_Message* msg, AJ_Message* reply)
{
    char guidStr[33];
    AJ_GUID localGuid;
    AJ_MarshalReplyMsg(msg, reply);
    AJ_GetLocalGUID(&localGuid);
    AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    return AJ_MarshalArgs(reply, "s", guidStr);
}

AJ_Status AJ_BusHandleBusMessage(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    char* name;
    char* oldOwner;
    char* newOwner;
    AJ_Message reply;

    /*
     * Check we actually have a message to handle
     */
    if (!msg->hdr) {
        return AJ_OK;
    }

    switch (msg->msgId) {
    case AJ_METHOD_PING:
        status = AJ_MarshalReplyMsg(msg, &reply);
        break;

    case AJ_METHOD_GET_MACHINE_ID:
        status = HandleGetMachineId(msg, &reply);
        break;

    case AJ_METHOD_INTROSPECT:
        status = AJ_HandleIntrospectRequest(msg, &reply);
        break;

    case AJ_METHOD_EXCHANGE_GUIDS:
        status = AJ_PeerHandleExchangeGUIDs(msg, &reply);
        break;

    case AJ_METHOD_GEN_SESSION_KEY:
        status = AJ_PeerHandleGenSessionKey(msg, &reply);
        break;

    case AJ_METHOD_EXCHANGE_GROUP_KEYS:
        status = AJ_PeerHandleExchangeGroupKeys(msg, &reply);
        break;

    case AJ_METHOD_AUTH_CHALLENGE:
        status = AJ_PeerHandleAuthChallenge(msg, &reply);
        break;

    case AJ_REPLY_ID(AJ_METHOD_EXCHANGE_GUIDS):
        status = AJ_PeerHandleExchangeGUIDsReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_AUTH_CHALLENGE):
        status = AJ_PeerHandleAuthChallengeReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_GEN_SESSION_KEY):
        status = AJ_PeerHandleGenSessionKeyReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_EXCHANGE_GROUP_KEYS):
        status = AJ_PeerHandleExchangeGroupKeysReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_CANCEL_SESSIONLESS):
        // handle return code here
        status = AJ_OK;
        break;

    case AJ_SIGNAL_SESSION_JOINED:
    case AJ_SIGNAL_NAME_ACQUIRED:
        // nothing to do here
        status = AJ_OK;
        break;

    case AJ_REPLY_ID(AJ_METHOD_ADD_MATCH):
    case AJ_REPLY_ID(AJ_METHOD_REMOVE_MATCH):
    case AJ_REPLY_ID(AJ_METHOD_CANCEL_ADVERTISE):
    case AJ_REPLY_ID(AJ_METHOD_ADVERTISE_NAME):
        if (msg->hdr->msgType == AJ_MSG_ERROR) {
            status = AJ_ERR_FAILURE;
        }
        break;

    case AJ_SIGNAL_NAME_OWNER_CHANGED:
        AJ_UnmarshalArgs(msg, "sss", &name, &oldOwner, &newOwner);
        if (newOwner && oldOwner && newOwner[0] == '\0') {
            AJ_GUID_DeleteNameMapping(oldOwner);
        }
        status = AJ_OK;
        break;

    default:
        if (msg->hdr->msgType == AJ_MSG_METHOD_CALL) {
            status = AJ_MarshalErrorMsg(msg, &reply, AJ_ErrRejected);
        }
        break;
    }
    if ((status == AJ_OK) && (msg->hdr->msgType == AJ_MSG_METHOD_CALL)) {
        status = AJ_DeliverMsg(&reply);
    }
    return status;
}

void AJ_BusSetPasswordCallback(AJ_BusAttachment* bus, AJ_AuthPwdFunc pwdCallback)
{
    bus->pwdCallback = pwdCallback;
}

AJ_Status AJ_BusAuthenticatePeer(AJ_BusAttachment* bus, const char* peerName, AJ_BusAuthPeerCallback callback, void* cbContext)
{
    return AJ_PeerAuthenticate(bus, peerName, callback, cbContext);
}

typedef struct {
    void* context;
    union {
        AJ_BusPropGetCallback Get;
        AJ_BusPropSetCallback Set;
    };
} PropCallback;

static AJ_Status PropAccess(AJ_Message* msg, PropCallback* cb, uint8_t op)
{
    AJ_Status status;
    AJ_Message reply;
    uint32_t propId;
    char sig[16];
    /*
     * Find out which property is being accessed and whether the access is a GET or SET
     */
    status = AJ_UnmarshalPropertyArgs(msg, &propId, sig, sizeof(sig));
    if (status == AJ_OK) {
        AJ_MarshalReplyMsg(msg, &reply);
        /*
         * Callback to let the application marshal or unmarshal the value
         */
        if (op == AJ_PROP_GET) {
            AJ_MarshalVariant(&reply, sig);
            status = cb->Get(&reply, propId, cb->context);
        } else {
            const char* variant;
            AJ_UnmarshalVariant(msg, &variant);
            /*
             * Check that the value has the expected signature
             */
            if (strcmp(sig, variant) == 0) {
                status = cb->Set(msg, propId, cb->context);
            } else {
                status = AJ_ERR_SIGNATURE;
            }
        }
    }
    if (status != AJ_OK) {
        AJ_MarshalStatusMsg(msg, &reply, status);
    }
    return AJ_DeliverMsg(&reply);
}

AJ_Status AJ_BusPropGet(AJ_Message* msg, AJ_BusPropGetCallback callback, void* context)
{
    PropCallback cb;
    cb.context = context;
    cb.Get = callback;
    return PropAccess(msg, &cb, AJ_PROP_GET);
}

AJ_Status AJ_BusPropSet(AJ_Message* msg, AJ_BusPropSetCallback callback, void* context)
{
    PropCallback cb;
    cb.context = context;
    cb.Set = callback;
    return PropAccess(msg, &cb, AJ_PROP_SET);
}
