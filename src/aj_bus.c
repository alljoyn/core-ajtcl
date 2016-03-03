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
#define AJ_MODULE BUS

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_msg.h>
#include <ajtcl/aj_bufio.h>
#include <ajtcl/aj_bus.h>
#include <ajtcl/aj_bus_priv.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_std.h>
#include <ajtcl/aj_introspect.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_about.h>
#include <ajtcl/aj_security.h>
#include <ajtcl/aj_authentication.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgBUS = 0;
#endif

static AJ_Session* AJ_BusGetOngoingHostedSessionByPort(AJ_BusAttachment* bus, uint16_t port);
static AJ_Session* AJ_BusGetPendingSession(AJ_BusAttachment* bus, uint32_t serial);
static AJ_Session* AJ_BusGetBoundSession(AJ_BusAttachment* bus, uint16_t port);
static void AJ_BusAddPendingSession(AJ_BusAttachment* bus, const char* host, uint16_t port, uint32_t serial);
static void AJ_BusRemovePendingSession(AJ_BusAttachment* bus, uint32_t serial);
static void AJ_BusAddBoundSession(AJ_BusAttachment* bus, uint32_t port, int multipoint);
static void AJ_BusRemoveBoundSession(AJ_BusAttachment* bus, uint16_t port);
static void AJ_BusAddOngoingSession(AJ_BusAttachment* bus, uint32_t sessionId, uint16_t port, int host, int multipoint, const char* otherParticipant);
static void AJ_BusReleaseOngoingSession(AJ_Session* session);
static void AJ_BusRemoveOngoingSession(AJ_BusAttachment* bus, uint32_t sessionId);

const char* AJ_GetUniqueName(AJ_BusAttachment* bus)
{
    return (*bus->uniqueName) ? bus->uniqueName : NULL;
}

AJ_Status AJ_BusRequestName(AJ_BusAttachment* bus, const char* name, uint32_t flags)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_BusRequestName(bus=0x%p, name=\"%s\", flags=0x%x)\n", bus, name, flags));


    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_REQUEST_NAME, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
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

    AJ_InfoPrintf(("AJ_BusReleaseName(bus=0x%p, name=\"%s\")\n", bus, name));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_RELEASE_NAME, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", name);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusAdvertiseName(AJ_BusAttachment* bus, const char* name, uint16_t transportMask, uint8_t op, uint8_t flags)
{
    AJ_Status status;
    AJ_Message msg;
    uint32_t msgId = (op == AJ_BUS_START_ADVERTISING) ? AJ_METHOD_ADVERTISE_NAME : AJ_METHOD_CANCEL_ADVERTISE;

    AJ_InfoPrintf(("AJ_BusAdvertiseName(bus=0x%p, name=\"%s\", transportMask=0x%x, op=%d.)\n", bus, name, transportMask, op));

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_BusDestination, 0, flags, AJ_METHOD_TIMEOUT);
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

    AJ_InfoPrintf(("AJ_BusFindAdvertiseName(bus=0x%p, namePrefix=\"%s\", op=%d.)\n", bus, namePrefix, op));

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", namePrefix);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusFindAdvertisedNameByTransport(AJ_BusAttachment* bus, const char* namePrefix, uint16_t transport, uint8_t op)
{
    AJ_Status status;
    AJ_Message msg;
    uint32_t msgId = (op == AJ_BUS_START_FINDING) ? AJ_METHOD_FIND_NAME_BY_TRANSPORT : AJ_METHOD_CANCEL_FIND_NAME_BY_TRANSPORT;

    AJ_InfoPrintf(("AJ_BusFindAdvertiseNameByTransport(bus=0x%p, namePrefix=\"%s\", transport=%d., op=%d.)\n", bus, namePrefix, transport, op));

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "sq", namePrefix, transport);
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

static AJ_Status UnmarshalSessionOpts(AJ_Message* msg, AJ_SessionOpts* opts)
{
    AJ_Status status;
    AJ_Arg dictionary;
    AJ_UnmarshalContainer(msg, &dictionary, AJ_ARG_ARRAY);
    while (TRUE) {
        const char* key;
        AJ_Arg entry;
        status = AJ_UnmarshalContainer(msg, &entry, AJ_ARG_DICT_ENTRY);
        if (status != AJ_OK) {
            break;
        }
        status = AJ_UnmarshalArgs(msg, "s", &key);
        if (status != AJ_OK) {
            break;
        }
        if (strcmp(key, "traf") == 0) {
            status = AJ_UnmarshalArgs(msg, "v", "y", &opts->traffic);
        } else if (strcmp(key, "multi") == 0) {
            status = AJ_UnmarshalArgs(msg, "v", "b", &opts->isMultipoint);
        } else if (strcmp(key, "prox") == 0) {
            status = AJ_UnmarshalArgs(msg, "v", "y", &opts->proximity);
        } else if (strcmp(key, "trans") == 0) {
            status = AJ_UnmarshalArgs(msg, "v", "q", &opts->transports);
        } else {
            AJ_SkipArg(msg);
        }
        if (status != AJ_OK) {
            break;
        }
        status = AJ_UnmarshalCloseContainer(msg, &entry);
        if (status != AJ_OK) {
            break;
        }
    }
    AJ_UnmarshalCloseContainer(msg, &dictionary);
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }
    return status;
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

AJ_Status AJ_BusBindSessionPort(AJ_BusAttachment* bus, uint16_t port, const AJ_SessionOpts* opts, uint8_t flags)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_BusBindSessionPort(bus=0x%p, port=%d., opts=0x%p)\n", bus, port, opts));

    if (!opts) {
        opts = &defaultSessionOpts;
    }
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_BIND_SESSION_PORT, AJ_BusDestination, 0, flags, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "q", port);
        status = MarshalSessionOpts(&msg, opts);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    if (status == AJ_OK) {
        AJ_BusAddBoundSession(bus, port, opts->isMultipoint);
    }
    return status;
}

AJ_Status AJ_BusUnbindSession(AJ_BusAttachment* bus, uint16_t port)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_BusUnbindSession(bus=0x%p, port=%d.)\n", bus, port));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_UNBIND_SESSION, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "q", port);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    if (status == AJ_OK) {
        AJ_BusRemoveBoundSession(bus, port);
    }
    return status;
}

AJ_Status AJ_BusCancelSessionless(AJ_BusAttachment* bus, uint32_t serialNum)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_BusCancelSessionless(bus=0x%p, serialNum=%d.)\n", bus, serialNum));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_CANCEL_SESSIONLESS, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
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
    uint32_t serialNum;

    AJ_InfoPrintf(("AJ_BusJoinSession(bus=0x%p, sessionHost=\"%s\", port=%d., opts=0x%p)\n", bus, sessionHost, port, opts));

    if (!opts) {
        opts = &defaultSessionOpts;
    }
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_JOIN_SESSION, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "sq", sessionHost, port);

        if (status == AJ_OK) {
            status = MarshalSessionOpts(&msg, opts);
        }
    }
    serialNum = msg.hdr->serialNum;
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    if (status == AJ_OK) {
        AJ_BusAddPendingSession(bus, sessionHost, port, serialNum);
    }
    return status;
}

AJ_Status AJ_BusLeaveSession(AJ_BusAttachment* bus, uint32_t sessionId)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_BusLeaveSession(bus=0x%p, sessionId=%d.)\n", bus, sessionId));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_LEAVE_SESSION, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
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

    AJ_InfoPrintf(("AJ_BusSetLinkTimeout(bus=0x%p, sessionId=%d., linkTimeout=%d.)\n", bus, sessionId, linkTimeout));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_SET_LINK_TIMEOUT, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        (void)AJ_MarshalArgs(&msg, "u", sessionId);
        (void)AJ_MarshalArgs(&msg, "u", linkTimeout);
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

AJ_Status AJ_BusSetSignalRule(AJ_BusAttachment* bus, const char* ruleString, uint8_t rule)
{
    return AJ_BusSetSignalRuleFlags(bus, ruleString, rule, 0);
}

AJ_Status AJ_BusSetSignalRuleSerial(AJ_BusAttachment* bus, const char* ruleString, uint8_t rule, uint8_t flags, uint32_t* serialNum)
{
    AJ_Status status;
    AJ_Message msg;
    uint32_t msgId = (rule == AJ_BUS_SIGNAL_ALLOW) ? AJ_METHOD_ADD_MATCH : AJ_METHOD_REMOVE_MATCH;

    AJ_InfoPrintf(("AJ_BusSetSignalRuleSerial(bus=0x%p, ruleString=\"%s\", rule=%d.)\n", bus, ruleString, rule));

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_DBusDestination, 0, flags, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        uint32_t sz = 0;
        uint8_t nul = 0;
        if (serialNum) {
            *serialNum = msg.hdr->serialNum;
        }
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

AJ_Status AJ_BusAddSignalRule(AJ_BusAttachment* bus, const char* signalName, const char* interfaceName, uint8_t rule)
{
    AJ_Status status;
    AJ_Message msg;
    const char* str[5];
    uint32_t msgId = (rule == AJ_BUS_SIGNAL_ALLOW) ? AJ_METHOD_ADD_MATCH : AJ_METHOD_REMOVE_MATCH;

    AJ_InfoPrintf(("AJ_BusAddSignalRule(bus=0x%p, signalName=\"%s\", interfaceName=\"%s\", rule=%d.)\n", bus, signalName, interfaceName, rule));

    str[0] = "type='signal',member='";
    str[1] = signalName;
    str[2] = "',interface='";
    str[3] = interfaceName;
    str[4] = "'";

    status = AJ_MarshalMethodCall(bus, &msg, msgId, AJ_DBusDestination, 0, 0, AJ_METHOD_TIMEOUT);
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

AJ_Status AJ_BusSetSignalRuleFlags(AJ_BusAttachment* bus, const char* ruleString, uint8_t rule, uint8_t flags)
{
    return AJ_BusSetSignalRuleSerial(bus, ruleString, rule, flags, NULL);
}

AJ_Status AJ_BusReplyAcceptSession(AJ_Message* msg, uint32_t acpt)
{
    AJ_Message reply;

    AJ_InfoPrintf(("AJ_BusReplyAcceptSession(msg=0x%p, accept=%d.)\n", msg, acpt));

    AJ_MarshalReplyMsg(msg, &reply);
    AJ_MarshalArgs(&reply, "b", acpt);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status HandleGetMachineId(AJ_Message* msg, AJ_Message* reply)
{
    char guidStr[33];
    AJ_GUID localGuid;

    AJ_InfoPrintf(("HandleGetMachineId(msg=0x%p, reply=0x%p)\n", msg, reply));

    AJ_MarshalReplyMsg(msg, reply);
    AJ_GetLocalGUID(&localGuid);
    AJ_GUID_ToString(&localGuid, guidStr, sizeof(guidStr));
    return AJ_MarshalArgs(reply, "s", guidStr);
}

AJ_Status AJ_BusRemoveSessionMember(AJ_BusAttachment* bus, uint32_t sessionId, const char* member)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_BusRemoveSessionMember(bus=0x%p, sessionId=%d, member=%s.)\n", bus, sessionId, member));
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_REMOVE_SESSION_MEMBER, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "us", sessionId, member);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;

}

AJ_Status AJ_BusPing(AJ_BusAttachment* bus, const char* name, uint32_t timeout)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("AJ_BusPing(bus=0x%p, name=%s, timeout=%d)\n", bus, name, timeout));
    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_BUS_PING, AJ_BusDestination, 0, 0, AJ_METHOD_TIMEOUT);
    if (status == AJ_OK) {
        AJ_MarshalArgs(&msg, "su", name, timeout);
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;

}

AJ_Status AJ_BusHandleBusMessage(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment* bus = msg->bus;
    char* languageTag;
    AJ_Message reply;
    uint32_t disposition;
    uint16_t port;
    uint32_t session;
    char* joiner;

    AJ_InfoPrintf(("AJ_BusHandleBusMessage(msg=0x%p)\n", msg));
    memset(&reply, 0, sizeof(AJ_Message));
    /*
     * Check we actually have a message to handle
     */
    if (!msg->hdr) {
        return AJ_OK;
    }

    switch (msg->msgId) {
    case AJ_METHOD_PING:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_PING\n"));
        status = AJ_MarshalReplyMsg(msg, &reply);
        break;

    case AJ_METHOD_GET_MACHINE_ID:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_GET_MACHINE_ID\n"));
        status = HandleGetMachineId(msg, &reply);
        break;

    case AJ_METHOD_INTROSPECT:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_INTROSPECT\n"));
        status = AJ_GetIntrospectionData(msg, &reply);
        break;

    case AJ_METHOD_GET_DESCRIPTION_LANG:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_GET_DESCRIPTION_LANG\n"));
        status = AJ_HandleGetDescriptionLanguages(msg, &reply);
        break;

    case AJ_METHOD_INTROSPECT_WITH_DESC:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_INTROSPECT_WITH_DESC\n"));
        AJ_UnmarshalArgs(msg, "s", &languageTag);
        status = AJ_HandleIntrospectRequest(msg, &reply, languageTag);
        break;

    case AJ_METHOD_EXCHANGE_GUIDS:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_EXCHANGE_GUIDS\n"));
        status = AJ_PeerHandleExchangeGUIDs(msg, &reply);
        break;

    case AJ_METHOD_GEN_SESSION_KEY:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_GEN_SESSION_KEY\n"));
        status = AJ_PeerHandleGenSessionKey(msg, &reply);
        break;

    case AJ_METHOD_EXCHANGE_GROUP_KEYS:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_EXCHANGE_GROUP_KEYS\n"));
        status = AJ_PeerHandleExchangeGroupKeys(msg, &reply);
        break;

    case AJ_METHOD_EXCHANGE_SUITES:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_EXCHANGE_SUITES\n"));
        status = AJ_PeerHandleExchangeSuites(msg, &reply);
        break;

    case AJ_METHOD_KEY_EXCHANGE:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_KEY_EXCHANGE\n"));
        status = AJ_PeerHandleKeyExchange(msg, &reply);
        break;

    case AJ_METHOD_KEY_AUTHENTICATION:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_KEY_AUTHENTICATION\n"));
        status = AJ_PeerHandleKeyAuthentication(msg, &reply);
        break;

    case AJ_METHOD_SEND_MANIFESTS:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_SEND_MANIFESTS\n"));
        status = AJ_PeerHandleSendManifests(msg, &reply);
        break;

    case AJ_METHOD_SEND_MEMBERSHIPS:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_SEND_MEMBERSHIPS\n"));
        status = AJ_PeerHandleSendMemberships(msg, &reply);
        break;

    case AJ_REPLY_ID(AJ_METHOD_EXCHANGE_GUIDS):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_EXCHANGE_GUIDS)\n"));
        status = AJ_PeerHandleExchangeGUIDsReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_GEN_SESSION_KEY):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_GEN_SESSION_KEY)\n"));
        status = AJ_PeerHandleGenSessionKeyReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_EXCHANGE_GROUP_KEYS):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_EXCHANGE_GROUP_KEYS)\n"));
        status = AJ_PeerHandleExchangeGroupKeysReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_EXCHANGE_SUITES):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_EXCHANGE_SUITES)\n"));
        status = AJ_PeerHandleExchangeSuitesReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_KEY_EXCHANGE):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_KEY_EXCHANGE)\n"));
        status = AJ_PeerHandleKeyExchangeReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_KEY_AUTHENTICATION):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_KEY_AUTHENTICATION)\n"));
        status = AJ_PeerHandleKeyAuthenticationReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_SEND_MANIFESTS):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_SEND_MANIFESTS)\n"));
        status = AJ_PeerHandleSendManifestsReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_SEND_MEMBERSHIPS):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_SEND_MEMBERSHIPS)\n"));
        status = AJ_PeerHandleSendMembershipsReply(msg);
        break;

    case AJ_REPLY_ID(AJ_METHOD_CANCEL_SESSIONLESS):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_CANCEL_SESSIONLESS)\n"));
        // handle return code here
        status = AJ_OK;
        break;

    case AJ_METHOD_ACCEPT_SESSION:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_METHOD_ACCEPT_SESSION\n"));
        status = AJ_UnmarshalArgs(msg, "qus", &port, &session, &joiner);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_MarshalReplyMsg(msg, &reply);
        if (AJ_OK != status) {
            break;
        }
        /* We only accept sessions to the Security Management port */
        if (AJ_SECURE_MGMT_PORT == port) {
            status = AJ_MarshalArgs(&reply, "b", TRUE);
            AJ_InfoPrintf(("Accepted session session_id=%u joiner=%s\n", session, joiner));
        } else {
            status = AJ_MarshalArgs(&reply, "b", FALSE);
            AJ_InfoPrintf(("Rejected session session_id=%u joiner=%s\n", session, joiner));
        }
        break;

    case AJ_SIGNAL_SESSION_JOINED:
    case AJ_SIGNAL_NAME_ACQUIRED:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_SIGNAL_{SESSION_JOINED|NAME_ACQUIRED}\n"));
        // nothing to do here
        status = AJ_OK;
        break;

    case AJ_REPLY_ID(AJ_METHOD_CANCEL_ADVERTISE):
    case AJ_REPLY_ID(AJ_METHOD_ADVERTISE_NAME):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_{CANCEL_ADVERTISE|ADVERTISE_NAME})\n"));
        if (msg->hdr->msgType == AJ_MSG_ERROR) {
            status = AJ_ERR_FAILURE;
        }
        break;

    case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT)\n"));
        if (AJ_MSG_ERROR == msg->hdr->msgType) {
            status = AJ_ERR_FAILURE;
            break;
        }
        status = AJ_UnmarshalArgs(msg, "uq", &disposition, &port);
        if (AJ_OK != status) {
            break;
        }
        if ((AJ_BINDSESSIONPORT_REPLY_SUCCESS == disposition) && (AJ_SECURE_MGMT_PORT == port)) {
            status = AJ_SecurityBound(bus);
        }
        break;

    case AJ_METHOD_ABOUT_GET_PROP:
        return AJ_AboutHandleGetProp(msg);

    case AJ_METHOD_ABOUT_GET_ABOUT_DATA:
        status = AJ_AboutHandleGetAboutData(msg, &reply);
        break;

    case AJ_METHOD_ABOUT_GET_OBJECT_DESCRIPTION:
        status = AJ_AboutHandleGetObjectDescription(msg, &reply);
        break;

    case AJ_METHOD_ABOUT_ICON_GET_PROP:
        return AJ_AboutIconHandleGetProp(msg);

    case AJ_METHOD_ABOUT_ICON_GET_URL:
        status = AJ_AboutIconHandleGetURL(msg, &reply);
        break;

    case AJ_METHOD_ABOUT_ICON_GET_CONTENT:
        status = AJ_AboutIconHandleGetContent(msg, &reply);
        break;

#ifdef ANNOUNCE_BASED_DISCOVERY
    case AJ_SIGNAL_ABOUT_ANNOUNCE:
        status = AJ_AboutHandleAnnounce(msg, NULL, NULL, NULL, NULL);
        break;
#endif

    case AJ_METHOD_SECURITY_GET_PROP:
        return AJ_SecurityGetProperty(msg);

    case AJ_METHOD_CLAIMABLE_CLAIM:
        status = AJ_SecurityClaimMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_RESET:
        status = AJ_SecurityResetMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_UPDATE_IDENTITY:
        status = AJ_SecurityUpdateIdentityMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_UPDATE_POLICY:
        status = AJ_SecurityUpdatePolicyMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_RESET_POLICY:
        status = AJ_SecurityResetPolicyMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_INSTALL_MEMBERSHIP:
        status = AJ_SecurityInstallMembershipMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_REMOVE_MEMBERSHIP:
        status = AJ_SecurityRemoveMembershipMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_START_MANAGEMENT:
        status = AJ_SecurityStartManagementMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_END_MANAGEMENT:
        status = AJ_SecurityEndManagementMethod(msg, &reply);
        break;

    case AJ_METHOD_MANAGED_INSTALL_MANIFESTS:
        status = AJ_SecurityInstallManifestsMethod(msg, &reply);
        break;

    default:
        AJ_InfoPrintf(("AJ_BusHandleBusMessage(): default\n"));
        if (msg->hdr->msgType == AJ_MSG_METHOD_CALL) {
            status = AJ_MarshalErrorMsg(msg, &reply, AJ_ErrRejected);
        }
        break;
    }
    if ((status == AJ_OK) && (msg->hdr->msgType == AJ_MSG_METHOD_CALL)) {
        status = AJ_DeliverMsg(&reply);
    }
    /*
     * Check if there is anything to announce
     */
    if (status == AJ_OK) {
        AJ_AboutAnnounce(bus);
        AJ_ApplicationStateSignal(bus);
    }
    return status;
}

void AJ_BusSetPasswordCallback(AJ_BusAttachment* bus, AJ_AuthPwdFunc pwdCallback)
{
    AJ_WarnPrintf(("AJ_BusSetPasswordCallback(bus=0x%p, pwdCallback=0x%p): This call is being deprecated.\n", bus, pwdCallback));
    bus->pwdCallback = pwdCallback;
}

/**
 * Set a callback for auth listener
 * until a password callback function has been set.
 *
 * @param bus          The bus attachment struct
 * @param authListenerCallback  The auth listener callback function.
 */
void AJ_BusSetAuthListenerCallback(AJ_BusAttachment* bus, AJ_AuthListenerFunc authListenerCallback) {
    AJ_InfoPrintf(("AJ_BusSetAuthListenerCallback(bus=0x%p, authListenerCallback=0x%p)\n", bus, authListenerCallback));
    bus->authListenerCallback = authListenerCallback;
}

/**
 * Set a callback for handling requests to factory reset any application state.
 *
 * @param bus                   The bus attachment struct
 * @param factoryResetCallback  The factory reset callback function.
 */
void AJ_BusSetFactoryResetCallback(AJ_BusAttachment* bus, AJ_FactoryResetFunc factoryResetCallback)
{
    AJ_InfoPrintf(("AJ_BusSetFactoryResetCallback(bus=0x%p, factoryResetCallback=0x%p)\n", bus, factoryResetCallback));
    bus->factoryResetCallback = factoryResetCallback;
}

/**
 * Set a callback for handling security policy change notifications.
 *
 * @param bus                    The bus attachment struct
 * @param policyChangedCallback  The policy changed callback function.
 */
void AJ_BusSetPolicyChangedCallback(AJ_BusAttachment* bus, AJ_PolicyChangedFunc policyChangedCallback)
{
    AJ_InfoPrintf(("AJ_BusSetPolicyChangedCallback(bus=0x%p, policyChangedCallback=0x%p)\n", bus, policyChangedCallback));
    bus->policyChangedCallback = policyChangedCallback;
}

AJ_Status AJ_BusAuthenticatePeer(AJ_BusAttachment* bus, const char* peerName, AJ_BusAuthPeerCallback callback, void* cbContext)
{
    AJ_InfoPrintf(("AJ_BusAuthenticatePeer(bus=0x%p, peerName=\"%s\", callback=0x%p, cbContext=0x%p)\n", bus, peerName, callback, cbContext));
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
    const char* sig;

    AJ_InfoPrintf(("PropAccess(msg=0x%p, cb=0x%p, op=%s)\n", msg, cb, (op == AJ_PROP_GET) ? "get" : "set"));

    /*
     * Find out which property is being accessed and whether the access is a GET or SET
     */
    status = AJ_UnmarshalPropertyArgs(msg, &propId, &sig);
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
                AJ_InfoPrintf(("PropAccess(): AJ_ERR_SIGNATURE\n"));
                status = AJ_ERR_SIGNATURE;
            }
        }
    }
    if (status != AJ_OK) {
        AJ_MarshalStatusMsg(msg, &reply, status);
    }
    return AJ_DeliverMsg(&reply);
}

static AJ_Status PropAccessAll(AJ_Message* msg, PropCallback* cb)
{
    AJ_Status status;
    AJ_Message reply;
    const char* iface;

    AJ_InfoPrintf(("PropAccessAll(msg=0x%p, cb=0x%p)\n", msg, cb));

    status = AJ_UnmarshalArgs(msg, "s", &iface);
    if (status == AJ_OK) {
        status = AJ_MarshalReplyMsg(msg, &reply);
    }
    if (status == AJ_OK) {
        status = AJ_MarshalAllPropertiesArgs(&reply, iface, cb->Get, cb->context);
    }
    if (status != AJ_OK) {
        AJ_MarshalStatusMsg(msg, &reply, status);
    }
    return AJ_DeliverMsg(&reply);
}

AJ_Status AJ_BusPropGet(AJ_Message* msg, AJ_BusPropGetCallback callback, void* context)
{
    PropCallback cb;

    AJ_InfoPrintf(("AJ_BusPropGet(msg=0x%p, callback=0x%p, context=0x%p)\n", msg, callback, context));

    cb.context = context;
    cb.Get = callback;
    return PropAccess(msg, &cb, AJ_PROP_GET);
}

AJ_Status AJ_BusPropSet(AJ_Message* msg, AJ_BusPropSetCallback callback, void* context)
{
    PropCallback cb;

    AJ_InfoPrintf(("AJ_BusPropSet(msg=0x%p, callback=0x%p, context=0x%p)\n", msg, callback, context));

    cb.context = context;
    cb.Set = callback;
    return PropAccess(msg, &cb, AJ_PROP_SET);
}

AJ_Status AJ_BusPropGetAll(AJ_Message* msg, AJ_BusPropGetCallback callback, void* context)
{
    PropCallback cb;

    AJ_InfoPrintf(("AJ_BusPropGetAll(msg=0x%p, callback=0x%p, context=0x%p)\n", msg, callback, context));

    cb.context = context;
    cb.Get = callback;
    return PropAccessAll(msg, &cb);
}

AJ_Status AJ_BusEnableSecurity(AJ_BusAttachment* bus, const uint32_t* suites, size_t numsuites)
{
    size_t i;

    AJ_InfoPrintf(("AJ_BusEnableSecurity(bus=0x%p, suites=0x%p)\n", bus, suites));

    /* Disable all first to undo any previous calls */
    memset((uint8_t*) bus->suites, 0, sizeof (bus->suites));
    for (i = 0; i < numsuites; i++) {
        AJ_EnableSuite(bus, suites[i]);
    }

    return AJ_SecurityInit(bus);
}

AJ_Session* AJ_BusGetOngoingSession(AJ_BusAttachment* bus, uint32_t sessionId)
{
    AJ_Session* iter;
    for (iter = bus->sessions; iter; iter = iter->next) {
        if (iter->sessionId == sessionId) {
            return iter;
        }
    }
    return NULL;
}

static AJ_Session* AJ_BusGetOngoingHostedSessionByPort(AJ_BusAttachment* bus, uint16_t port)
{
    AJ_Session* iter;
    for (iter = bus->sessions; iter; iter = iter->next) {
        if (iter->sessionId != 0 && iter->host && iter->sessionPort == port) {
            return iter;
        }
    }
    return NULL;
}

static AJ_Session* AJ_BusGetPendingSession(AJ_BusAttachment* bus, uint32_t serial)
{
    AJ_Session* iter;
    for (iter = bus->sessions; iter; iter = iter->next) {
        if (iter->sessionId == 0 && !iter->host && iter->joinCallSerial == serial) {
            return iter;
        }
    }
    return NULL;
}

static AJ_Session* AJ_BusGetBoundSession(AJ_BusAttachment* bus, uint16_t port)
{
    AJ_Session* iter;
    for (iter = bus->sessions; iter; iter = iter->next) {
        if (iter->sessionId == 0 && iter->host && iter->sessionPort == port) {
            return iter;
        }
    }
    return NULL;
}

static AJ_Session* SessionAlloc()
{
    AJ_Session* session = AJ_Malloc(sizeof(AJ_Session));
    if (session) {
        AJ_MemZeroSecure(session, sizeof(AJ_Session));
    } else {
        AJ_ErrPrintf(("Could not allocate Session structure -- out of memory.\n"));
    }
    return session;
}

static void AJ_BusAddPendingSession(AJ_BusAttachment* bus, const char* host, uint16_t port, uint32_t serial)
{
    size_t hostlen = strlen(host);
    AJ_Session* session = SessionAlloc();
    if (!session) {
        return;
    }
    session->host = FALSE;
    session->sessionPort = port;
    session->joinCallSerial = serial;

    /*
     * We leave multipoint as FALSE and always fill in otherParticipant.
     * If the session turns out to be multipoint, we'll correct this in
     * the JoinSession reply handler (see ProcessBusMessages)
     */
    session->multipoint = FALSE;
    session->otherParticipant = AJ_Malloc(hostlen + 1);
    if (!session->otherParticipant) {
        AJ_ErrPrintf(("Could not allocate Session structure -- out of memory.\n"));
        AJ_BusReleaseOngoingSession(session);
        return;
    }
    strncpy(session->otherParticipant, host, hostlen);
    session->otherParticipant[hostlen] = '\0';

    session->next = bus->sessions;
    bus->sessions = session;
}

static void AJ_BusRemovePendingSession(AJ_BusAttachment* bus, uint32_t serial)
{
    AJ_Session* iter;
    AJ_Session* prev = NULL;

    for (iter = bus->sessions; iter; prev = iter, iter = iter->next) {
        if (iter->sessionId == 0 && !iter->host && iter->joinCallSerial == serial) {
            break;
        }
    }

    if (!iter) {
        return;
    }

    if (prev) {
        prev->next = iter->next;
    } else {
        bus->sessions = iter->next;
    }

    AJ_BusReleaseOngoingSession(iter);
}

static void AJ_BusAddBoundSession(AJ_BusAttachment* bus, uint32_t port, int multipoint)
{
    AJ_Session* session = SessionAlloc();
    if (!session) {
        return;
    }

    session->host = TRUE;
    session->sessionPort = port;
    session->multipoint = multipoint;

    session->next = bus->sessions;
    bus->sessions = session;
}

static void AJ_BusRemoveBoundSession(AJ_BusAttachment* bus, uint16_t port)
{
    AJ_Session* iter;
    AJ_Session* prev = NULL;

    for (iter = bus->sessions; iter; prev = iter, iter = iter->next) {
        if (iter->sessionId == 0 && iter->host && iter->sessionPort == port) {
            break;
        }
    }

    if (!iter) {
        return;
    }

    if (prev) {
        prev->next = iter->next;
    } else {
        bus->sessions = iter->next;
    }

    AJ_BusReleaseOngoingSession(iter);
}

static void AJ_BusAddOngoingSession(AJ_BusAttachment* bus, uint32_t sessionId, uint16_t port, int host, int multipoint, const char* otherParticipant)
{
    AJ_Session* session = SessionAlloc();
    if (!session) {
        return;
    }

    session->sessionId = sessionId;
    session->sessionPort = port;
    session->host = host;
    session->multipoint = multipoint;
    if (otherParticipant) {
        size_t otherlen = strlen(otherParticipant);
        session->otherParticipant = AJ_Malloc(otherlen + 1);
        if (!session->otherParticipant) {
            AJ_ErrPrintf(("Could not allocate Session structure -- out of memory.\n"));
            AJ_BusReleaseOngoingSession(session);
            return;
        }
        strncpy(session->otherParticipant, otherParticipant, otherlen);
        session->otherParticipant[otherlen] = '\0';
    } else {
        session->otherParticipant = NULL;
    }

    session->next = bus->sessions;
    bus->sessions = session;
}

static void AJ_BusReleaseOngoingSession(AJ_Session* session)
{
    if (session->otherParticipant) {
        AJ_Free(session->otherParticipant);
    }
    AJ_Free(session);
}

static void AJ_BusRemoveOngoingSession(AJ_BusAttachment* bus, uint32_t sessionId)
{
    AJ_Session* iter;
    AJ_Session* prev = NULL;

    for (iter = bus->sessions; iter; prev = iter, iter = iter->next) {
        if (iter->sessionId == sessionId) {
            break;
        }
    }

    if (!iter) {
        return;
    }

    if (prev) {
        prev->next = iter->next;
    } else {
        bus->sessions = iter->next;
    }

    AJ_BusReleaseOngoingSession(iter);
}

void AJ_BusRemoveAllSessions(AJ_BusAttachment* bus)
{
    while (bus->sessions) {
        AJ_Session* session = bus->sessions;
        bus->sessions = session->next;
        AJ_BusReleaseOngoingSession(session);
    }
}

AJ_Status AJ_BusHandleSessionJoined(AJ_Message* msg)
{
    uint16_t sessionPort;
    uint32_t sessionId;
    char* joiner;
    AJ_Session* boundsession;

    AJ_Status status = AJ_UnmarshalArgs(msg, "qus", &sessionPort, &sessionId, &joiner);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("AJ_BusHandleSessionJoined(msg=0x%p): Unmarshal error\n", msg));
        return status;
    }

    boundsession = AJ_BusGetBoundSession(msg->bus, sessionPort);
    if (boundsession) {
        int multipoint = boundsession->multipoint;
        if (multipoint) {
            /* if there already is an OngoingSession entry for this session,
             * we don't have to add another one. */
            AJ_Session* ongoing = AJ_BusGetOngoingHostedSessionByPort(msg->bus, sessionPort);
            if (ongoing != NULL) {
                return AJ_OK;
            } else {
                AJ_BusAddOngoingSession(msg->bus, sessionId, sessionPort, TRUE, TRUE, NULL);
            }
        } else {
            AJ_BusAddOngoingSession(msg->bus, sessionId, sessionPort, TRUE, FALSE, joiner);
        }
    } else {
        AJ_ErrPrintf(("AJ_BusHandleSessionJoined(msg=0x%p): unknown session port\n", msg));
        return AJ_ERR_FAILURE;
    }
    return AJ_OK;
}

AJ_Status AJ_BusHandleSessionLost(AJ_Message* msg)
{
    uint32_t sessionId;

    AJ_Status status = AJ_UnmarshalArgs(msg, "u", &sessionId);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("AJ_BusHandleSessionLost(msg=0x%p): Unmarshal error\n", msg));
        return status;
    }
    AJ_BusRemoveOngoingSession(msg->bus, sessionId);
    return AJ_OK;
}

AJ_Status AJ_BusHandleSessionLostWithReason(AJ_Message* msg)
{
    uint32_t sessionId;
    uint32_t reason;

    AJ_Status status = AJ_UnmarshalArgs(msg, "uu", &sessionId, &reason);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("AJ_BusHandleSessionLostWithReason(msg=0x%p): Unmarshal error\n", msg));
        return status;
    }
    AJ_BusRemoveOngoingSession(msg->bus, sessionId);
    return AJ_OK;
}

AJ_Status AJ_BusHandleJoinSessionReply(AJ_Message* msg)
{
    uint32_t resultCode;
    uint32_t sessionId;
    AJ_SessionOpts opts = { 0 };
    AJ_Status status;
    AJ_Session* session;

    if (msg->hdr->msgType == AJ_MSG_ERROR) {
        AJ_InfoPrintf(("AJ_BusHandleSessionJoinSessionReply(msg=0x%p): error=%s.\n", msg, msg->error));
        /* it's OK for the JoinSession reply to be an error message - it simply means
         * we can remove the pending session here */
        AJ_BusRemovePendingSession(msg->bus, msg->replySerial);
        return AJ_OK;
    }

    status = AJ_UnmarshalArgs(msg, "uu", &resultCode, &sessionId);
    if (status != AJ_OK) {
        goto unmarshal_error;
    }

    status = UnmarshalSessionOpts(msg, &opts);
    if (status != AJ_OK) {
        goto unmarshal_error;
    }

    /* now we can fill in the pending AJ_Session structure */
    session = AJ_BusGetPendingSession(msg->bus, msg->replySerial);
    if (session) {
        session->sessionId = sessionId;
        session->multipoint = opts.isMultipoint;
        if (opts.isMultipoint) {
            AJ_Free(session->otherParticipant);
            session->otherParticipant = NULL;
        }
    } else {
        AJ_ErrPrintf(("AJ_BusHandleSessionJoinSessionReply(msg=0x%p): JoinSession reply for unknown JoinSession call\n", msg));
        return AJ_ERR_FAILURE;
    }

    return AJ_OK;

unmarshal_error:
    AJ_ErrPrintf(("AJ_BusHandleJoinSessionReply(msg=0x%p): Unmarshal error\n", msg));
    return status;
}
