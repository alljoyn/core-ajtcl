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

#define AJ_MODULE MQTT

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/fcntl.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <mosquitto.h>

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_crypto.h>

#define INVALID_SOCKET (-1)

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgMQTT = 1;
uint8_t dbgNET = 0;
#endif

typedef enum _SendSignals {
    SEND_NONE = 0,
    SEND_MP_SESSION_CHANGED = 1,
    SEND_SESSION_LOST = 2,
    SEND_BOTH = 3
} SendSignals;

static AJ_Status MQTT_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout);
static AJ_Status MQTT_Send(AJ_IOBuffer* buf);

/*
 * Placeholder for a scope GUID
 */
static const char* scope = "AllJoyn";

static const char* clientId = NULL;

static bool IsDirectLeaf(const char* name)
{
    int32_t l1 = AJ_StringFindFirstOf(name, ".");
    return (strncmp(name + l1, ".0", 2) == 0);
}

static bool IsRoutingNode(const char* name)
{
    int32_t l1 = AJ_StringFindFirstOf(name, ".");
    return (strcmp(name + l1, ".1") == 0);
}

static char* GetUniqueName(const char* guid, const char* num)
{
    size_t l0 = strlen(guid);
    size_t l1 = strlen(num);
    char* buf = AJ_Malloc(l0 + l1 + 2);
    if (buf) {
        char* p = buf;

        memcpy(p, guid, l0);
        p += l0;
        *p++ = '.';

        memcpy(p, num, l1);
        p += l1;
        *p++ = 0;
    }
    return buf;
}

static char* BuildTopic(const char* name, uint32_t sessionId, const char* iface, const char* member)
{
    char sess[11];
    size_t l0 = strlen(scope);
    int32_t l1 = 0;
    int32_t l2 = 0;
    int32_t l3 = 0;
    int32_t l4 = 0;
    int32_t l5 = 0;
    int32_t l6 = 0;

    if (name) {
        if (name[0] == ':') {
            l1 = AJ_StringFindFirstOf(name, ".");
            if (l1 < 0) {
                l1 = strlen(name);
            } else {
                l2 = strlen(name) - l1 - 1;
            }
        } else {
            l1 = strlen(name);
        }
    }

    if (sessionId) {
        sprintf(sess, "%u", sessionId);
        l3 = strlen(sess);
    }
    if (iface) {
        if (iface[0] == ':') {

            l4 = AJ_StringFindFirstOf(iface, ".");
            if (l4 < 0) {
                l4 = strlen(iface);
            } else {
                l5 = strlen(iface) - l4 - 1;
            }
        } else {
            l4 = strlen(iface);
        }

    }
    if (member) {
        l6 = AJ_StringFindFirstOf(member, " ");
        if (l6 < 0) {
            l6 = strlen(member);
        }
    }
    char* buf = AJ_Malloc(l0 + l1 + l2 + l3 + l4 + l5 + l6 + 7);
    if (buf) {
        char* p = buf;

        memcpy(p, scope, l0);
        p += l0;
        *p++ = '/';

        memcpy(p, name, l1);
        p += l1;

        if (l2) {
            *p++ = '/';
            memcpy(p, name + l1 + 1, l2);
            p += l2;
        }
        if (l3) {
            *p++ = '/';
            memcpy(p, sess, l3);
            p += l3;
        }
        if (l4) {
            *p++ = '/';
            memcpy(p, iface, l4);
            p += l4;
        }

        if (l5) {
            *p++ = '/';
            memcpy(p, iface + l4 + 1, l5);
            p += l5;
        }
        if (l6) {
            *p++ = '/';
            memcpy(p, member, l6);
            p += l6;
        }

        *p++ = 0;
    }
    return buf;
}

static char* FindItem(char* rule, const char* key)
{
    char* item = NULL;
    size_t keyLen = strlen(key);
    size_t ruleLen = strlen(rule);

    while (ruleLen >= keyLen + 4) {
        if (strncmp(rule, key, keyLen) == 0) {
            size_t valLen = 0;
            char* val = rule + keyLen + 2;
            char* p = val;
            while (*p && (*p++ != '\'')) {
                ++valLen;
            }
            item = AJ_Malloc(valLen + 1);
            if (item) {
                memcpy(item, val, valLen);
                item[valLen] = 0;
            }
            break;
        }
        while (--ruleLen && *rule++ != ',') {
        }
    }
    return item;
}

typedef struct _SessionMember {
    struct _SessionMember* next;
    char name[AJ_MAX_NAME_SIZE + 1];
} SessionMember;

typedef struct _SessionRecord {
    uint8_t isMultipoint;            /* TRUE if this is a multi-point session */
    uint8_t isHost;                  /* TRUE if this device is the session host */
    uint16_t port;                   /* Session port - only valid if this devices is the session host */
    uint32_t sessionId;              /* The session id */
    struct _SessionRecord* next;     /* Linked list of sessions */
    char host[AJ_MAX_NAME_SIZE + 1]; /* Name of session host */
    SessionMember* members;          /* Members in this session */
} SessionRecord;

static SessionRecord* sessionList;

static SessionRecord* AllocSession(const char* host, uint32_t sessionId);

static AJ_Status DummyRecv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    /*
     * We don't expect this to be called because the message is already buffered.
     */
    AJ_ASSERT(!"DummyRecv called");
    return AJ_ERR_FAILURE;
}

static AJ_Status DummySend(AJ_IOBuffer* buf)
{
    return AJ_OK;
}

/*
 * Swaps the receive and transmit buffers so we can unmarshal from the tx buffer and marshal into
 * the rx buffer as we intercept or transform incoming and outgoing messages.
 */
static void SwapRxTx(AJ_BusAttachment* bus, AJ_TxFunc send, AJ_RxFunc recv)
{
    AJ_IOBuffer tmp = bus->sock.tx;
    bus->sock.tx = bus->sock.rx;
    bus->sock.tx.send = send;
    bus->sock.tx.direction = AJ_IO_BUF_TX;
    bus->sock.rx = tmp;
    bus->sock.rx.recv = recv;
    bus->sock.rx.direction = AJ_IO_BUF_RX;
}

static AJ_Status InjectNameOwnerChangedSignal(AJ_BusAttachment* bus, const char* id)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_InfoPrintf(("Pushing NAME_OWNER_CHANGED for \"%s\"\n", id));

    SwapRxTx(bus, DummySend, DummyRecv);
    status = AJ_MarshalSignal(bus, &msg, AJ_SIGNAL_NAME_OWNER_CHANGED, NULL, 0, 0, 0);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "sss", id, id, "");
        if (status == AJ_OK) {
            AJ_DeliverMsg(&msg);
        }
    }
    SwapRxTx(bus, MQTT_Send, MQTT_Recv);
    return status;
}

/*
 * Copies a bus name into a buffer of known size.
 */
static void CopyName(char* dest, const char* src)
{
    strncpy(dest, src, AJ_MAX_NAME_SIZE + 2);
    dest[AJ_MAX_NAME_SIZE + 2] = 0;
}

/*
 * Copies a bus name into a buffer of known size.
 */
static void CopyRouterName(char* dest, const char* src)
{
    int32_t l1 = AJ_StringFindFirstOf(src, ".");
    assert(l1 >= 0);
    strncpy(dest, src, l1);
    strncpy(dest + l1, ".1", 2);
    dest[l1 + 2] = 0;
}

/*
 * Subscribes to presence messages for peers we are in session with or tracking for some other reason.
 */
static AJ_Status SubscribeToPresenceTopic(struct mosquitto* mosq, const char* peer)
{
    AJ_Status status;
    char* topic;

    topic = BuildTopic("presence", 0, peer, NULL);
    if (topic) {
        int ret;
        AJ_InfoPrintf(("subscribe to topic \"%s\"\n", topic));
        ret = mosquitto_subscribe(mosq, NULL, topic, 0);
        if (ret != MOSQ_ERR_SUCCESS) {
            AJ_ErrPrintf(("SubscribeToPresenceTopic(): mosquitto_subscribe() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
            status = AJ_ERR_RESOURCES;
        }
        AJ_Free(topic);
    } else {
        status = AJ_ERR_RESOURCES;
    }
    if (!IsDirectLeaf(peer)) {
        /* Subscribe to Routing node's presence topic */
        char routingNode[AJ_MAX_NAME_SIZE + 1];
        CopyRouterName(routingNode, peer);
        topic = BuildTopic("presence", 0, routingNode, NULL);
        if (topic) {
            int ret;
            AJ_InfoPrintf(("subscribe to topic \"%s\"\n", topic));
            ret = mosquitto_subscribe(mosq, NULL, topic, 0);
            if (ret != MOSQ_ERR_SUCCESS) {
                AJ_ErrPrintf(("SubscribeToPresenceTopic(): mosquitto_subscribe() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
                status = AJ_ERR_RESOURCES;
            }
            AJ_Free(topic);
        } else {
            status = AJ_ERR_RESOURCES;
        }
    }
    return status;
}

/*
 * Called when we intercept a LeaveSession method call
 */
static AJ_Status UnsubscribeFromSession(struct mosquitto* mosq, SessionRecord* sess)
{
    AJ_Status status;
    char* topic;

    topic = BuildTopic(sess->host, sess->sessionId, NULL, NULL);
    if (topic) {
        int ret;
        AJ_InfoPrintf(("unsubscribe from topic \"%s\"\n", topic));
        ret = mosquitto_unsubscribe(mosq, NULL, topic);
        if (ret != MOSQ_ERR_SUCCESS) {
            AJ_ErrPrintf(("UnsubscribeFromSession(): mosquitto_unsubscribe() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
            status = AJ_ERR_RESOURCES;
        }
        AJ_Free(topic);
    } else {
        status = AJ_ERR_RESOURCES;
    }
    return status;
}

static AJ_Status SubscribeToSession(struct mosquitto* mosq, SessionRecord* sess)
{
    AJ_Status status;
    char* topic;

    topic = BuildTopic(sess->host, sess->sessionId, NULL, NULL);
    if (topic) {
        int ret;
        AJ_InfoPrintf(("subscribe to topic \"%s\"\n", topic));
        ret = mosquitto_subscribe(mosq, NULL, topic, 0);
        if (ret != MOSQ_ERR_SUCCESS) {
            AJ_ErrPrintf(("SubscribeToSession(): mosquitto_subscribe() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
            status = AJ_ERR_RESOURCES;
        }
        AJ_Free(topic);
    } else {
        status = AJ_ERR_RESOURCES;
    }
    return status;
}

static SessionRecord* LookupSessionByPort(uint16_t port)
{
    SessionRecord* bindEntry;
    SessionRecord* mpSessionEntry;
    SessionRecord* list;

    /* Search for the bind entry and multipoint entry */
    for (list = sessionList; list && (!bindEntry || (bindEntry->isMultipoint && !mpSessionEntry)); list = list->next) {
        if (list->port == port) {
            if (list->sessionId == 0) {
                bindEntry = list;
            } else if (list->isMultipoint) {
                mpSessionEntry = list;
            }

        }
    }
    if (!bindEntry) {
        return NULL;
    } else if (mpSessionEntry) {
        return mpSessionEntry;
    } else {
        /* Create new session entry */
        uint32_t sessionId;

        AJ_RandBytes((uint8_t*)&sessionId, sizeof(sessionId));
        SessionRecord* sess = AllocSession(bindEntry->host, sessionId);
        sess->port = bindEntry->port;
        sess->isHost = TRUE;
        sess->isMultipoint = bindEntry->isMultipoint;

        return sess;
    }
}

static SessionRecord* LookupSessionById(uint32_t sessionId)
{
    SessionRecord* list;

    for (list = sessionList; list; list = list->next) {
        if (list->sessionId == sessionId) {
            break;
        }
    }
    return list;
}

static void ProtectTxBuffer(AJ_BusAttachment* bus, AJ_IOBuffer* save)
{
    AJ_IOBuffer* txBuf = &bus->sock.tx;

    *save = *txBuf;
    txBuf->writePtr = txBuf->bufStart = (uint8_t*)(((ptrdiff_t)txBuf->writePtr + 7) & ~7);
    txBuf->readPtr = txBuf->bufStart;
}

static void ResetTxBuffer(AJ_BusAttachment* bus, AJ_IOBuffer* save)
{
    bus->sock.tx = *save;
}

static bool FindMember(SessionRecord* sess, const char* name)
{
    SessionMember* member;
    /*
     * Check if member is present.
     */
    for (member = sess->members; member; member = member->next) {
        if (strcmp(name, member->name) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static AJ_Status AddSessionMember(AJ_BusAttachment* bus, struct mosquitto* mosq, SessionRecord* sess, const char* name)
{
    SessionMember* member;
    if (FindMember(sess, name)) {
        AJ_WarnPrintf(("Member already listed session=%d name=\"%s\"\n", sess->sessionId, name));
        return TRUE;
    }
    member = AJ_Malloc(sizeof(*member));
    if (!member) {
        return AJ_ERR_RESOURCES;
    }
    CopyName(member->name, name);
    member->next = sess->members;
    sess->members = member;
    /*
     * Subscribe to the session if this is the first member
     */
    if (sess->members->next == NULL) {
        SubscribeToSession(mosq, sess);
    }
    SubscribeToPresenceTopic(mosq, name);
    /*
     * If we are the host and this is a multi-point session send a member changed (added) signal to the other members
     */
    if (sess->isMultipoint && sess->isHost) {
        AJ_IOBuffer save;
        AJ_Message signal;
        /*
         * Protect the current contents of the transmit buffer while we marshal and deliver the message
         */
        ProtectTxBuffer(bus, &save);
        /*
         * Multicast MP_SESSION_CHANGED to all current members
         */
        AJ_MarshalSignal(bus, &signal, AJ_SIGNAL_MP_SESSION_CHANGED_WITH_REASON, NULL, sess->sessionId, 0, 0);
        AJ_MarshalArgs(&signal, "usbu", sess->sessionId, member->name, TRUE /*added*/, AJ_MPSESSIONCHANGED_REMOTE_MEMBER_ADDED);
        AJ_DeliverMsg(&signal);
        /*
         * Send out "catch-up" MP_SESSION_CHANGED signals just to the joiner
         */
        for (member = sess->members->next; member; member = member->next) {
            AJ_MarshalSignal(bus, &signal, AJ_SIGNAL_MP_SESSION_CHANGED_WITH_REASON, name, 0, 0, 0);
            AJ_MarshalArgs(&signal, "usbu", sess->sessionId, member->name, TRUE /*added*/, AJ_MPSESSIONCHANGED_REMOTE_MEMBER_ADDED);
            AJ_DeliverMsg(&signal);
        }
        ResetTxBuffer(bus, &save);
    }
    return AJ_OK;
}

static AJ_Status DelSessionMember(AJ_BusAttachment* bus, SessionRecord* sess, const char* name, uint8_t sendSignals)
{
    SessionMember* prev = NULL;
    SessionMember* member;
    AJ_Status status = AJ_ERR_UNKNOWN;

    for (member = sess->members; member; member = member->next) {
        int32_t l1 = AJ_StringFindFirstOf(name, ".");
        if (strcmp(name, member->name) == 0 || (IsRoutingNode(name) && (strncmp(name, member->name, l1) == 0))) {
            if (prev) {
                prev->next = member->next;
            } else {
                sess->members = member->next;
            }

            if (sendSignals & SEND_MP_SESSION_CHANGED) {

                /*
                 * Send (to ourself) a session lost or member changed signal
                 */
                if (sess->isMultipoint) {
                    AJ_Message signal;
                    status = AJ_MarshalSignal(bus, &signal, AJ_SIGNAL_MP_SESSION_CHANGED_WITH_REASON, clientId, 0, 0, 0);
                    if (status == AJ_OK) {
                        status = AJ_MarshalArgs(&signal, "usbu", sess->sessionId, member->name, FALSE /*removed*/, AJ_MPSESSIONCHANGED_REMOTE_MEMBER_REMOVED);
                    }
                    if (status == AJ_OK) {
                        AJ_DeliverMsg(&signal);
                    }
                }
            }
            if (sendSignals & SEND_SESSION_LOST) {

                if (!sess->isMultipoint || (sess->members == NULL)) {
                    AJ_Message signal;
                    status = AJ_MarshalSignal(bus, &signal, AJ_SIGNAL_SESSION_LOST_WITH_REASON, clientId, 0, 0, 0);
                    if (status == AJ_OK) {
                        status = AJ_MarshalArgs(&signal, "uu", sess->sessionId, (sendSignals == SEND_BOTH) ? AJ_SESSIONLOST_REMOTE_END_CLOSED_ABRUPTLY : AJ_SESSIONLOST_REMOTE_END_LEFT_SESSION);
                    }
                    if (status == AJ_OK) {
                        AJ_DeliverMsg(&signal);
                    }
                }
            }


            AJ_Free(member);
            break;
        }
        prev = member;
    }

    if (member && strcmp(clientId, member->name) != 0) {
        return AJ_OK;
    } else {
        return AJ_ERR_UNKNOWN;
    }
}

/*
 * Called when a peer we are monitoring disconnects
 */
static void DetachSessionMember(AJ_BusAttachment* bus, struct mosquitto* mosq, const char* name)
{
    SessionRecord* prev = NULL;
    SessionRecord* sess = sessionList;

    AJ_InfoPrintf(("DetachSessionMember \"%s\"\n", name));

    while (sess) {
        SessionRecord* next = sess->next;
        DelSessionMember(bus, sess, name, SEND_BOTH);
        /*
         * Check if the session record should be discarded.
         */
        if (sess->members || (sess->sessionId == 0)) {
            prev = sess;
        } else if (sess->isHost) {
            prev = sess;
            /*
             * We are a session host and the old session has expired so generate a new session id.
             */
            UnsubscribeFromSession(mosq, sess);

            AJ_RandBytes((uint8_t*)&sess->sessionId, sizeof(sess->sessionId));
        } else {
            /*
             * Unlink and free the dead session
             */
            if (prev) {
                prev->next = next;
            } else {
                sessionList = next;
            }
            AJ_Free(sess);
        }
        sess = next;
    }
}

static SessionRecord* AllocSession(const char* host, uint32_t sessionId)
{
    SessionRecord* newSess = AJ_Malloc(sizeof(SessionRecord));

    if (!newSess) {
        return NULL;
    }
    memset(newSess, 0, sizeof(SessionRecord));
    newSess->sessionId = sessionId;
    CopyName(newSess->host, host);
    newSess->next = sessionList;
    sessionList = newSess;

    return newSess;
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
 * This duplicates a private function in aj_bus.c
 */
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

static AJ_Status InterceptBindSessionPort(struct mosquitto* mosq, AJ_Message* msg)
{
    uint16_t port;
    AJ_SessionOpts opts;
    uint32_t sessionId;
    SessionRecord* sess;

    AJ_RandBytes((uint8_t*)&sessionId, sizeof(sessionId));
    sess = AllocSession(clientId, 0);
    if (!sess) {
        return AJ_ERR_RESOURCES;
    }
    AJ_UnmarshalArgs(msg, "q", &port);
    UnmarshalSessionOpts(msg, &opts);
    sess->port = port;
    sess->isHost = TRUE;
    sess->isMultipoint = opts.isMultipoint;
    return AJ_OK;
}

/*
 * ADD_MATCH or REMOVE_MATCH
 */
static void InterceptSendMatchRule(struct mosquitto* mosq, AJ_Message* msg)
{
    AJ_Status status;
    char* rule;
    char* typ;

    status = AJ_UnmarshalArgs(msg, "s", &rule);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("InterceptSendMatchRule %s\n", AJ_StatusText(status)));
        return;
    }
    typ = FindItem(rule, "type");

    AJ_InfoPrintf(("InterceptSendMatchRule \"%s\"\n", rule));
    if (typ && (strcmp(typ, "signal") == 0)) {
        char* iface = FindItem(rule, "interface");
        char* member = FindItem(rule, "member");
        char* topic = BuildTopic("+/+", 0, iface, member);
        if (topic) {
            if (msg->msgId == AJ_METHOD_ADD_MATCH) {
                AJ_InfoPrintf(("InterceptSendMatchRule subscribe to \"%s\"\n", topic));
                (void) mosquitto_subscribe(mosq, NULL, topic, 0);
            } else {
                AJ_InfoPrintf(("InterceptSendMatchRule unsubscribe from \"%s\"\n", topic));
                (void) mosquitto_unsubscribe(mosq, NULL, topic);
            }
            AJ_Free(topic);
        }
        AJ_Free(iface);
        AJ_Free(member);
    }
    AJ_Free(typ);
}

static const AJ_SessionOpts defaultSessionOpts = {
    AJ_SESSION_TRAFFIC_MESSAGES,
    AJ_SESSION_PROXIMITY_ANY,
    AJ_TRANSPORT_ANY,
    FALSE
};

static void InterceptSendAcceptSessionReply(struct mosquitto* mosq, AJ_Message* msg)
{
    AJ_SessionOpts opts;
    AJ_BusAttachment* bus = msg->bus;
    uint32_t accepted;
    uint32_t sessId = msg->sessionId;
    uint32_t replySerial = msg->replySerial;
    SessionRecord* sess;
    AJ_Message reply;
    char dest[AJ_MAX_NAME_SIZE + 1];
    char leaf[AJ_MAX_NAME_SIZE + 1];

    if (IsDirectLeaf(msg->destination)) {
        CopyName(dest, msg->destination);
        CopyName(leaf, msg->destination);
    } else {
        CopyRouterName(dest, msg->destination);
        CopyName(leaf, msg->destination);
    }


    AJ_UnmarshalArgs(msg, "b", &accepted);
    AJ_CloseMsg(msg);

    SwapRxTx(bus, MQTT_Send, MQTT_Recv);

    AJ_ASSERT(AJ_IO_BUF_AVAIL(&bus->sock.tx) == 0);

    sess = LookupSessionById(sessId);
    if (!sess) {
        AJ_ErrPrintf(("Session information missing\n"));
        accepted = FALSE;
    }
    /*
     * Custom marshal a reply for the original JoinSession call
     */
    memset(&reply, 0, sizeof(reply));
    reply.msgId = AJ_METHOD_JOIN_SESSION;
    reply.bus = bus;
    reply.destination = dest;
    reply.replySerial = replySerial;
    AJ_MarshalMsgCustom(&reply, AJ_MSG_METHOD_RET, 0);
    AJ_MarshalArgs(&reply, "uu", accepted ? AJ_JOINSESSION_REPLY_SUCCESS : AJ_JOINSESSION_REPLY_REJECTED, sessId);
    /*
     * Multicast sessions need the multicast flag in the options
     */
    opts = defaultSessionOpts;
    if (sess) {
        opts.isMultipoint = sess->isMultipoint;
    }
    MarshalSessionOpts(&reply, &opts);
    AJ_DeliverMsg(&reply);
    if (accepted) {
        AddSessionMember(bus, mosq, sess, leaf);
    }
}

static void InterceptSendJoinSession(AJ_Message* msg)
{
    AJ_BusAttachment* bus = msg->bus;
    AJ_SessionOpts opts;
    const char* sessHost;
    uint16_t sessPort;
    char dest[AJ_MAX_NAME_SIZE + 1];

    /*
     * We won't be getting a reply to this message
     */
    AJ_ReleaseReplyContext(msg);
    /*
     * Unmarshal the message to get the session host, port, and options
     */
    AJ_UnmarshalArgs(msg, "sq", &sessHost, &sessPort);

    UnmarshalSessionOpts(msg, &opts);
    CopyName(dest, sessHost);
    AJ_CloseMsg(msg);
    SwapRxTx(bus, MQTT_Send, MQTT_Recv);
    /*
     * Remarshal the message with the destination replaced
     */
    AJ_MarshalMethodCall(bus, msg, AJ_METHOD_JOIN_SESSION, dest, 0, 0, AJ_METHOD_TIMEOUT);
    AJ_MarshalArgs(msg, "sq", dest, sessPort);
    MarshalSessionOpts(msg, &opts);
    AJ_DumpMsg("InterceptSendJoinSession", msg, FALSE);
    AJ_DeliverMsg(msg);
}

static void InterceptSendLeaveSession(AJ_Message* msg)
{
    AJ_BusAttachment* bus = msg->bus;
    uint32_t sessionId;

    /*
     * We won't be getting a reply to this message
     */
    AJ_ReleaseReplyContext(msg);
    /*
     * Unmarshal the message to get the session host, port, and options
     */
    AJ_UnmarshalArgs(msg, "u", &sessionId);

    SessionRecord* sess = LookupSessionById(sessionId);
    AJ_CloseMsg(msg);
    SwapRxTx(bus, MQTT_Send, MQTT_Recv);

    if (sess->isMultipoint) {
        AJ_Status status = AJ_MarshalSignal(bus, msg, AJ_SIGNAL_MP_SESSION_CHANGED_WITH_REASON, NULL, sessionId, 0, 0);
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(msg, "usbu", sess->sessionId, clientId, FALSE /*removed*/, AJ_MPSESSIONCHANGED_REMOTE_MEMBER_REMOVED);
        }
    } else {
        AJ_Status status = AJ_MarshalSignal(bus, msg, AJ_SIGNAL_SESSION_LOST_WITH_REASON, NULL, sessionId, 0, 0);
        if (status == AJ_OK) {
            status = AJ_MarshalArgs(msg, "uu", sess->sessionId, AJ_SESSIONLOST_REMOTE_END_LEFT_SESSION);
        }
    }
    AJ_DumpMsg("InterceptSendLeaveSession", msg, FALSE);
    AJ_DeliverMsg(msg);

}


/*
 * We don't have a routing node so various management messages must be handled locally.
 */
static uint8_t InterceptSend(AJ_Message* msg)
{
    AJ_Status status;
    AJ_BusAttachment* bus = msg->bus;
    struct mosquitto* mosq = (struct mosquitto*)bus->sock.rx.context;
    AJ_Message tmp;
    AJ_Message reply;

    switch (msg->msgId) {

    case AJ_METHOD_ADD_MATCH:
    case AJ_METHOD_REMOVE_MATCH:
    case AJ_METHOD_BIND_SESSION_PORT:
    case AJ_REPLY_ID(AJ_METHOD_ACCEPT_SESSION):
    case AJ_METHOD_JOIN_SESSION:
    case AJ_METHOD_LEAVE_SESSION:
        break;

    default:
        return FALSE;
    }

    AJ_DumpMsg("InteceptSend", msg, FALSE);

    reply.msgId = 0;
    SwapRxTx(bus, DummySend, DummyRecv);
#ifndef NDEBUG
    /*
     * Prevent assert check in case there is a message currently being unmarshaled.
     * It is safe because we are unmarshaling from a different buffer.
     */
    bus->currentMsg = NULL;
#endif
    /*
     * If we are intercepting a method reply we need to register a reply context otherwise the
     * unmarshaler will reject the message.
     */
    if (msg->hdr->msgType == AJ_MSG_METHOD_RET) {
        AJ_MsgHeader hdr;
        tmp.msgId = msg->msgId & 0xFFFFFF;
        hdr.serialNum = msg->replySerial;
        hdr.msgType = AJ_MSG_METHOD_CALL;
        tmp.hdr = &hdr;
        AJ_AllocReplyContext(&tmp, 0);
    }

    status = AJ_UnmarshalMsg(bus, &tmp, 0);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("InterceptSend - unmarshal failed %s\n", AJ_StatusText(status)));
        AJ_ASSERT(status == AJ_OK);
    }

    switch (tmp.msgId) {

    case AJ_REPLY_ID(AJ_METHOD_ACCEPT_SESSION):
        InterceptSendAcceptSessionReply(mosq, &tmp);
        break;

    case AJ_METHOD_ADD_MATCH:
    case AJ_METHOD_REMOVE_MATCH:
        InterceptSendMatchRule(mosq, &tmp);
        if (!(msg->hdr->flags & AJ_FLAG_NO_REPLY_EXPECTED)) {
            AJ_MarshalReplyMsg(&tmp, &reply);
        }
        AJ_CloseMsg(&tmp);
        SwapRxTx(bus, MQTT_Send, MQTT_Recv);
        break;

    case AJ_METHOD_BIND_SESSION_PORT:
        status = InterceptBindSessionPort(mosq, &tmp);
        if (!(msg->hdr->flags & AJ_FLAG_NO_REPLY_EXPECTED)) {
            AJ_MarshalReplyMsg(&tmp, &reply);
            AJ_MarshalArgs(&reply, "uq", (status == AJ_OK) ? 1 : 3, 0);
            AJ_DeliverMsg(&reply);
        }
        AJ_CloseMsg(&tmp);
        SwapRxTx(bus, MQTT_Send, MQTT_Recv);
        break;

    case AJ_METHOD_JOIN_SESSION:
        InterceptSendJoinSession(&tmp);
        break;

    case AJ_METHOD_LEAVE_SESSION:
        InterceptSendLeaveSession(&tmp);
        break;
    }
    memset(msg, 0, sizeof(*msg));
    return TRUE;
}

static uint8_t InterceptRecvJoinSession(AJ_Message* msg)
{
    AJ_Status status;
    AJ_BusAttachment* bus = msg->bus;
    AJ_SessionOpts opts;
    const char* sessHost;
    uint16_t sessPort;
    SessionRecord* sess;
    char sender[AJ_MAX_NAME_SIZE + 1];

    CopyName(sender, msg->sender);
    status = AJ_UnmarshalArgs(msg, "sq", &sessHost, &sessPort);
    AJ_InfoPrintf(("InterceptRecvJoinSession %s %s %u\n", msg->sender, sessHost, sessPort));
    if (status == AJ_OK) {
        AJ_ASSERT(strcmp(sessHost, clientId) == 0);
        status = UnmarshalSessionOpts(msg, &opts);
    }

    sess = LookupSessionByPort(sessPort);
    if (!sess || FindMember(sess, sender)) {
        AJ_Message reply;
        /*
         * Reject the join request.
         */
        AJ_MarshalReplyMsg(msg, &reply);

        AJ_MarshalArgs(&reply, "uu", 0, sess ? AJ_JOINSESSION_REPLY_ALREADY_JOINED : AJ_JOINSESSION_REPLY_REJECTED);
        MarshalSessionOpts(&reply, &defaultSessionOpts);
        AJ_CloseMsg(msg);
        AJ_DeliverMsg(&reply);
        return TRUE;
    }

    /*
     * Morph JoinSession into an AcceptSession method call
     */
    if (status == AJ_OK) {
        /*
         * First truncate the arguments
         */
        AJ_ResetArgs(msg);
        msg->bus->sock.rx.writePtr = msg->bus->sock.rx.readPtr;
        msg->bodyBytes = 0;
        /*
         * Replace the signature
         */
        msg->signature = "qusa{sv}";
        /*
         * Change the message id
         */
        msg->msgId = AJ_METHOD_ACCEPT_SESSION;
        msg->sessionId = sess->sessionId;
        /*
         * Marshal the new arguments.
         */
        SwapRxTx(bus, DummySend, DummyRecv);
        status = AJ_MarshalArgs(msg, "qus", sessPort, msg->sessionId, sender);
        if (status == AJ_OK) {
            status = MarshalSessionOpts(msg, &opts);
        }
        SwapRxTx(bus, MQTT_Send, MQTT_Recv);
    }
    if (status != AJ_OK) {
        AJ_ErrPrintf(("InterceptRecvJoinSession failed %s\n", AJ_StatusText(status)));
        AJ_CloseMsg(msg);
        return TRUE;
    }
    return FALSE;
}

static uint8_t InterceptRecvJoinSessionReply(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;

    if (msg->hdr->msgType == AJ_MSG_METHOD_RET) {
        uint32_t replyCode;
        uint32_t sessionId;
        status = AJ_UnmarshalArgs(msg, "uu", &replyCode, &sessionId);
        if ((status == AJ_OK) && (replyCode == AJ_JOINSESSION_REPLY_SUCCESS)) {
            struct mosquitto* mosq = (struct mosquitto*)msg->bus->sock.rx.context;
            SessionRecord* sess = AllocSession(msg->sender, sessionId);
            if (sess) {
                AJ_SessionOpts opts;

                status = UnmarshalSessionOpts(msg, &opts);
                if (status == AJ_OK) {
                    status = AddSessionMember(msg->bus, mosq, sess, msg->sender);
                }
                if (status == AJ_OK) {
                    sess->isMultipoint = opts.isMultipoint;
                } else {
                    AJ_ASSERT(sess == sessionList);
                    sessionList = sess->next;
                    AJ_Free(sess);
                    sess = NULL;
                }
            } else {
                status = AJ_ERR_RESOURCES;
            }
        }
        AJ_ResetArgs(msg);
    }
    if (status != AJ_OK) {
        /*
         * TODO - this should be treated as a fatal error. Our internal state is
         * inconsistent.
         */
        AJ_ErrPrintf(("JoinSession failed to complete %s\n", AJ_StatusText(status)));
        return TRUE;
    }
    return FALSE;
}

static uint8_t InterceptNameOwnerChanged(AJ_Message* msg)
{
    struct mosquitto* mosq = (struct mosquitto*)msg->bus->sock.rx.context;
    const char* name;

    AJ_UnmarshalArgs(msg, "s", &name);
    DetachSessionMember(msg->bus, mosq, name);
    AJ_ResetArgs(msg);
    return FALSE;
}

static uint8_t InterceptRecvSessionLost(AJ_Message* msg)
{
    AJ_Status status;
    SessionRecord* sess;
    uint32_t sessionId;
    uint32_t reason;
    uint8_t ret = FALSE;

    status = AJ_UnmarshalArgs(msg, "uu", &sessionId, &reason);
    if (status == AJ_OK) {
        AJ_InfoPrintf(("SessionLost %u\n", sessionId));
        sess = LookupSessionById(sessionId);
        if (sess) {
            status = DelSessionMember(msg->bus, sess, msg->sender, SEND_NONE);
            if (status == AJ_OK) {
                ret = FALSE;
            } else {
                ret = TRUE;
            }
        }
    }
    AJ_ResetArgs(msg);
    return ret;
}

static uint8_t InterceptRecvSessionChangedWithReason(AJ_Message* msg)
{
    AJ_Status status;
    SessionRecord* sess;
    struct mosquitto* mosq = (struct mosquitto*)msg->bus->sock.rx.context;
    const char* name;
    uint32_t sessionId;
    uint32_t added;
    uint32_t reason;
    uint8_t ret = FALSE;
    status = AJ_UnmarshalArgs(msg, "usbu", &sessionId, &name, &added, &reason);
    if (status == AJ_OK) {
        AJ_InfoPrintf(("SessionChanged %u %s \"%s\"\n", sessionId, added ? "added" : "removed", name));
        sess = LookupSessionById(sessionId);
        if (sess) {
            if (added) {
                AddSessionMember(msg->bus, mosq, sess, name);
            } else {
                status = DelSessionMember(msg->bus, sess, name, SEND_SESSION_LOST);
                if (status == AJ_OK) {
                    ret = FALSE;
                } else {
                    ret = TRUE;
                }
            }
        }
    }
    AJ_ResetArgs(msg);
    return ret;
}

static uint8_t intercepting = FALSE;
static AJ_Message* currentMsg;

static uint8_t InterceptIncoming(AJ_Message* msg)
{
    /*
     * We might be unmarshalling an intercepted outgoing message
     */
    if (intercepting) {
        return FALSE;
    }
    switch (msg->msgId) {

    case AJ_SIGNAL_NAME_OWNER_CHANGED:
        return InterceptNameOwnerChanged(msg);

    case AJ_METHOD_JOIN_SESSION:
        return InterceptRecvJoinSession(msg);

    case AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION):
        return InterceptRecvJoinSessionReply(msg);

    case AJ_SIGNAL_MP_SESSION_CHANGED_WITH_REASON:
        if (strcmp(msg->sender, clientId) == 0) {
            return FALSE;
        } else {
            return InterceptRecvSessionChangedWithReason(msg);
        }

    case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
        if (strcmp(msg->sender, clientId) == 0) {
            return FALSE;
        } else {
            return InterceptRecvSessionLost(msg);
        }

    case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
        return FALSE;

    default:
        return FALSE;
    }
    return TRUE;
}

static uint8_t InterceptOutgoing(AJ_Message* msg)
{
    AJ_IOBuffer* rxBuf = &msg->bus->sock.rx;
    size_t rx = AJ_IO_BUF_AVAIL(rxBuf);

    currentMsg = msg;

    /*
     * Ths might be a replacement for an intercepted outgoing message
     */
    if (intercepting) {
        return FALSE;
    }
    intercepting = TRUE;
    if (InterceptSend(msg)) {
        AJ_ASSERT((rx == 0) || (rx == AJ_IO_BUF_AVAIL(rxBuf)));
        intercepting = FALSE;
        return TRUE;
    } else {
        intercepting = FALSE;
        return FALSE;
    }
}

static AJ_Status MQTT_Send(AJ_IOBuffer* buf)
{
    struct mosquitto* mosq = (struct mosquitto*)buf->context;
    int ret;
    size_t tx = AJ_IO_BUF_AVAIL(buf);
    char* topic;
    int retain = FALSE;

    if (!tx) {
        return AJ_OK;
    }
    if (currentMsg->destination) {
        topic = BuildTopic(currentMsg->destination, 0, NULL, NULL);
    } else {
        if (currentMsg->sessionId) {
            SessionRecord* sess = LookupSessionById(currentMsg->sessionId);
            topic = BuildTopic(sess->host, currentMsg->sessionId, NULL, NULL);
        } else {
            topic = BuildTopic(clientId, 0, currentMsg->iface, currentMsg->member);
        }
        if (currentMsg->hdr->flags & AJ_FLAG_SESSIONLESS) {
            retain = TRUE;
        }
    }
    if (!topic) {
        return AJ_ERR_RESOURCES;
    }

    AJ_InfoPrintf(("MQTT_Send() %d bytes, topic=\"%s\"\n", tx, topic));

    assert(buf->direction == AJ_IO_BUF_TX);

    ret = mosquitto_publish(mosq, NULL, topic, tx, buf->readPtr, 0, retain);
    AJ_Free(topic);
    AJ_IO_BUF_RESET(buf);

    if (ret != MOSQ_ERR_SUCCESS) {
        AJ_ErrPrintf(("MQTT_Send(): mosquitto_publish() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
        return AJ_ERR_WRITE;
    }
    ret = mosquitto_loop_write(mosq, 1);
    if (ret != MOSQ_ERR_SUCCESS) {
        AJ_ErrPrintf(("MQTT_Send(): mosquitto_loop_write() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
        return AJ_ERR_WRITE;
    }
    AJ_InfoPrintf(("MQTT_Send(): status=AJ_OK\n"));
    return AJ_OK;
}

/*
 * An eventfd handle used for interrupting a network read blocked on select
 */
static int interruptFd = INVALID_SOCKET;

/*
 * True if we are blocked in select
 */
static uint8_t blocked;

/*
 * This function is called to cancel a pending select.
 */
void AJ_Net_Interrupt()
{
    if (blocked) {
        uint64_t u64;
        if (write(interruptFd, &u64, sizeof(u64)) < 0) {
            AJ_ErrPrintf(("AJ_Net_Interrupt(): write() failed. errno=\"%s\"\n", strerror(errno)));
        }
    }
}

static void OnMessageRecv(struct mosquitto* mosq, void* ctx, const struct mosquitto_message* msg)
{
    AJ_BusAttachment* bus = (AJ_BusAttachment*)ctx;
    AJ_IOBuffer* buf = &bus->sock.rx;
    bool result;
    int ret;
    size_t rx = AJ_IO_BUF_SPACE(buf);

    AJ_InfoPrintf(("OnMessageRecv(): received %d bytes topic \"%s\"\n", msg->payloadlen, msg->topic));

    /*
     * Check for presence publication
     */
    ret = mosquitto_topic_matches_sub("+/presence/+/+", msg->topic, &result);
    if (result == TRUE) {
        if (msg->payloadlen == 0) {
            char** topics;
            int numTopics;
            ret = mosquitto_sub_topic_tokenise(msg->topic, &topics, &numTopics);
            if ((ret == MOSQ_ERR_SUCCESS) && (numTopics >= 3)) {
                /*
                 * Indicates absence - inject a NameOwnerChanged message into the receive buffer
                 */
                char* uqn = GetUniqueName(topics[2], topics[3]);
                if (uqn) {
                    buf->status = InjectNameOwnerChangedSignal(bus, uqn);
                    AJ_Free(uqn);
                }
            }
        }
        return;
    }

    if (msg->payloadlen > rx) {
        AJ_ErrPrintf(("OnMessageRecv(): payload too large\n"));
        buf->status = AJ_ERR_READ;
    } else {
        memcpy(buf->writePtr, msg->payload, msg->payloadlen);
        buf->writePtr += msg->payloadlen;
        buf->status = AJ_OK;
    }
    AJ_InfoPrintf(("OnMessageRecv(): received %d bytes topic \"%s\" returning\n", msg->payloadlen, msg->topic));

}

static uint8_t reconnected = FALSE;

static void DisconnectHandler(struct mosquitto* mosq, void* ctx, int rc)
{
    reconnected = FALSE;
    if (rc) {
        AJ_ErrPrintf(("Disconnect from broker. error=\"%s\"\n", mosquitto_strerror(rc)));
        rc = mosquitto_reconnect(mosq);
        if (rc == MOSQ_ERR_SUCCESS) {
            reconnected = TRUE;
        } else {
            AJ_ErrPrintf(("Failed to reconnect to broker. error=\"%s\"\n", mosquitto_strerror(rc)));
        }
    }
}


/*
 * Time in seconds for PING keep-alive
 */
#define MQTT_PING_INTERVAL 60

/*
 * Maximum time in seconds to block in select().
 * This must be less than MQTT_PING_INTERVAL
 */
#define MAX_BLOCK_SECS ((MQTT_PING_INTERVAL / 2) - 1)

static AJ_Status MQTT_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    struct mosquitto* mosq = (struct mosquitto*)buf->context;
    AJ_Status status = AJ_OK;
    int ret;
    int sock = mosquitto_socket(mosq);

    //AJ_InfoPrintf(("MQTT_Recv(buf=0x%p, len=%d, timeout=%u)\n", buf, len, timeout));

    assert(buf->direction == AJ_IO_BUF_RX);
    buf->status = AJ_OK;

    while (TRUE) {
        while (TRUE) {
            /*
             * Can't block for too long because we need to let MQTT do work
             */
            uint32_t blockTime = min(timeout, MAX_BLOCK_SECS * 1000);
            struct timeval tv = { blockTime / 1000, 1000 * (blockTime % 1000) };
            int rc = 0;
            fd_set fds;
            int maxFd = sock;
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            if (interruptFd >= 0) {
                FD_SET(interruptFd, &fds);
                maxFd = max(maxFd, interruptFd);
            }
            blocked = TRUE;
            rc = select(maxFd + 1, &fds, NULL, NULL, &tv);
            blocked = FALSE;
            timeout -= blockTime;
            if (rc < 0) {
                AJ_ErrPrintf(("MQTT_Recv(): select(%d) failed. errno=\"%s\"\n", blockTime, strerror(errno)));
                status = AJ_ERR_READ;
                break;
            }
            if (rc == 0) {
                if (timeout != 0) {
                    /*
                     * Let mosquitto do work
                     */
                    ret = mosquitto_loop_misc(mosq);
                    if (ret != MOSQ_ERR_SUCCESS) {
                        AJ_ErrPrintf(("MQTT_Recv(): mosquitto_loop_misc() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
                        status = AJ_ERR_READ;
                        break;
                    }
                    continue;
                }
                status = AJ_ERR_TIMEOUT;
                break;
            }
            if ((interruptFd >= 0) && FD_ISSET(interruptFd, &fds)) {
                uint64_t u64;
                if (read(interruptFd, &u64, sizeof(u64)) < 0) {
                    AJ_ErrPrintf(("MQTT_Recv(): read() failed during interrupt. errno=\"%s\"\n", strerror(errno)));
                }
                status = AJ_ERR_INTERRUPTED;
                break;
            }
            /*
             * If we got here we might have something to read
             */
            ret = mosquitto_loop_read(mosq, 1);
            if (ret != MOSQ_ERR_SUCCESS) {
                AJ_ErrPrintf(("MQTT_Recv(%d): mosquitto_loop_read() failed. error=\"%s\"\n", blockTime, mosquitto_strerror(ret)));
                status = AJ_ERR_READ;
                break;
            }
            status = buf->status;
            if (mosquitto_want_write(mosq)) {
                ret = mosquitto_loop_write(mosq, 1);
            }
            if ((status != AJ_OK) || AJ_IO_BUF_AVAIL(buf)) {
                break;
            }
        }
        if (reconnected) {
            reconnected = FALSE;
            sock = mosquitto_socket(mosq);
            continue;
        }
        break;
    }
    if ((status != AJ_OK) && (status != AJ_ERR_TIMEOUT) && (status != AJ_ERR_INTERRUPTED)) {
        AJ_ErrPrintf(("MQTT_Recv() error %s\n", AJ_StatusText(status)));
    } else {
        /*
         * Let mosquitto do work
         */
        ret = mosquitto_loop_misc(mosq);
        if (ret != MOSQ_ERR_SUCCESS) {
            AJ_ErrPrintf(("MQTT_Recv(): mosquitto_loop_misc() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
            return AJ_ERR_READ;
        }
    }
    return status;
}

#ifdef AJ_MQTT_BROKER
#define _STRINGIFY(str) # str
#define STRINGIFY(str) _STRINGIFY(str)
static const char* brokerHost = STRINGIFY(AJ_MQTT_BROKER);
#undef STRINGIFY
#undef _STRINGIFY
#else
static const char* brokerHost = "127.0.0.1";
#endif

static int brokerPort = 1883;

static uint8_t rxData[4096];
static uint8_t txData[4096];

AJ_Status AJ_Connect(AJ_BusAttachment* bus, const char* service, uint32_t timeout)
{
    char* topic;
    struct mosquitto* mosq;
    int ret;

    clientId = bus->uniqueName;

    AJ_InfoPrintf(("AJ_Connect service=%s, clientId=%s\n", service ? service : "<none>", clientId));

    mosquitto_lib_init();

    if (service) {
        brokerHost = strtok(service, ":");
        brokerPort = atoi(strtok(NULL, ":"));
    }
    mosq = mosquitto_new(clientId, TRUE, bus);
    if (!mosq) {
        mosquitto_lib_cleanup();
        return AJ_ERR_RESOURCES;
    }

    AJ_IOBufInit(&bus->sock.rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, mosq);
    bus->sock.rx.recv = MQTT_Recv;
    AJ_IOBufInit(&bus->sock.tx, txData, sizeof(txData), AJ_IO_BUF_TX, mosq);
    bus->sock.tx.send = MQTT_Send;

    interruptFd = eventfd(0, O_NONBLOCK);  // Use O_NONBLOCK instead of EFD_NONBLOCK due to bug in OpenWrt's uCLibc
    if (interruptFd < 0) {
        AJ_ErrPrintf(("AJ_Net_Connect(): failed to created interrupt event\n"));
        goto ConnectError;
    }
    /*
     * The "will" will remove the presence message on abnormal disconnect.
     */
    topic = BuildTopic("presence", 0, clientId, NULL);
    if (!topic) {
        goto ConnectError;
    }
    mosquitto_will_set(mosq, topic, 0, NULL, 0, TRUE);
    /*
     * Connect to the broker - using local host for now
     */
    ret = mosquitto_connect(mosq, brokerHost, brokerPort, MQTT_PING_INTERVAL);
    if (ret != MOSQ_ERR_SUCCESS) {
        AJ_ErrPrintf(("AJ_Net_Connect(): mosquitto_connect() to %s failed. error=%s", brokerHost, mosquitto_strerror(ret)));
        goto ConnectError;
    }
    AJ_AlwaysPrintf(("AJ_Net_Connect(): connected to MQTT broker %s\n", brokerHost));
    mosquitto_disconnect_callback_set(mosq, DisconnectHandler);
    /*
     * Retained message indicates presence - the payload doesn't matter so long as it isn't NULL
     */
    ret = mosquitto_publish(mosq, NULL, topic, 5, "TRUE", 0, TRUE);
    AJ_Free(topic);
    if (ret != MOSQ_ERR_SUCCESS) {
        AJ_ErrPrintf(("AJ_Net_Connect(): mosquitto_publish() failed. error=%s", mosquitto_strerror(ret)));
        goto ConnectError;
    }
    /*
     * We needs to be able to intercept messages
     */
    AJ_RegisterMsgInterceptors(InterceptIncoming, InterceptOutgoing);
    /*
     * No limit on the number of inflight messages
     */
    mosquitto_max_inflight_messages_set(mosq, 0);
    /*
     * Register callbacks for sent and received messages
     */
    mosquitto_message_callback_set(mosq, OnMessageRecv);
    /*
     * Subscribe to our unique name
     */
    topic = BuildTopic(bus->uniqueName, 0, NULL, NULL);
    if (!topic) {
        goto ConnectError;
    }
    ret = mosquitto_subscribe(mosq, NULL, topic, 0);
    AJ_InfoPrintf(("AJ_Net_Connect(): subscribed to topic \"%s\"\n", topic));

    AJ_Free(topic);
    if (ret != MOSQ_ERR_SUCCESS) {
        AJ_ErrPrintf(("AJ_Net_Connect(): mosquitto_subscribe() failed. error=\"%s\"\n", mosquitto_strerror(ret)));
        goto ConnectError;
    }
    /*
     * Let the subscription get sent
     */
    if (mosquitto_loop_misc(mosq) != MOSQ_ERR_SUCCESS) {
        goto ConnectError;
    }
    return AJ_OK;

ConnectError:
    if (mosq) {
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        bus->sock.rx.context = NULL;
        bus->sock.tx.context = NULL;
    }
    mosquitto_lib_cleanup();
    if (interruptFd != INVALID_SOCKET) {
        close(interruptFd);
        interruptFd = INVALID_SOCKET;
    }
    return AJ_ERR_CONNECT;
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
    struct mosquitto* mosq = (struct mosquitto*)netSock->rx.context;
    if (mosq) {
        /*
         * This will let interested peers know we are going away
         */
        char* topic = BuildTopic("presence", 0, clientId, NULL);
        if (topic) {
            mosquitto_publish(mosq, NULL, topic, 0, NULL, 0, TRUE);
            (void) mosquitto_loop_write(mosq, 1);
            AJ_Free(topic);
        }
        /*
         * Now disconnect
         */
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        mosq = NULL;
        netSock->rx.context = NULL;
        netSock->tx.context = NULL;
    }
    mosquitto_lib_cleanup();
    if (interruptFd >= 0) {
        close(interruptFd);
        interruptFd = INVALID_SOCKET;
    }
}
