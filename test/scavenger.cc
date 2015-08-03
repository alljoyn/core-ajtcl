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
#define AJ_MODULE SCAVENGER

extern "C" {
#include <ajtcl/aj_target.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_msg.h>
}

#include <mosquitto.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <map>
#include <list>
#include <string>
#include <set>


/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgSCAVENGER = 1;
#endif

#define UNMARSHAL_TIMEOUT  (1000 * 5)

static std::string Scope = "AllJoyn";

/**
    TODO: when do we clear out these maps?

    Not on disconnect, because those signals are still active if the broker stayed up.
    If the broker went down, however, we want to clear the lists.  But we don't have
    any way of knowing why we were disconnected.  It could have been a simple
    network hiccup.
 */

typedef std::set<std::string> IdList;
typedef std::map<std::string, IdList> ClientIds;
static ClientIds clients;
// map client ==> list of id


typedef std::set<std::string> TopicList;
typedef std::map<std::pair<std::string, std::string>, TopicList> SenderTopicMap;
// map client, id ==> topic
static SenderTopicMap active_topics;


struct Timeout {
    std::string client;
    std::string id;
    std::string topic;
};

// map timeout ==> pair of (clientid, topic)
typedef std::multimap<time_t, Timeout> TimeoutMap;
static TimeoutMap timeouts;


static struct mosquitto* mosq = NULL;

static uint32_t HandleTimeouts()
{
    // check for timeouts
    AJ_Time now;
    AJ_InitTimer(&now);

    TimeoutMap::iterator last = timeouts.begin();

    while ((last != timeouts.end()) && (last->first <= now.seconds)) {
        // time to erase?
        Timeout& to = last->second;
        const std::string& topic = to.topic;

        std::pair<std::string, std::string> clientid = std::make_pair(to.client, to.id);

        SenderTopicMap::iterator it = active_topics.find(clientid);
        if (it != active_topics.end()) {
            TopicList& topics = it->second;
            TopicList::iterator it2 = topics.find(topic);
            if (it2 != topics.end()) {
                // pull the topic string!
                AJ_InfoPrintf(("Canceling %s due to timeout\n", topic.c_str()));
                mosquitto_publish(mosq, NULL, topic.c_str(), 0, NULL, 0, TRUE);
                mosquitto_loop_write(mosq, 1);
                topics.erase(it2);

                if (topics.empty()) {
                    active_topics.erase(it);
                }
            }
        }

        timeouts.erase(last);
        last = timeouts.begin();
    }

    if (timeouts.empty()) {
        return UNMARSHAL_TIMEOUT;
    } else {
        return 1000 * (timeouts.begin()->first - now.seconds);
    }
}


static void HandleClientRemoved(const std::string& client, const std::string& id)
{
    AJ_InfoPrintf(("HandleClientRemoved: client=%s, id=%s\n", client.c_str(), id.c_str()));

    // we don't care about this anymore; and we don't want to get our own publish
    const std::string topic = Scope + '/' + client + '/' + id + "/+/+";
    mosquitto_unsubscribe(mosq, NULL, topic.c_str());
    mosquitto_loop_misc(mosq);

    // 'id' was lost!
    if (id == "0") {
        std::pair<std::string, std::string> clientid = std::make_pair(client, id);
        SenderTopicMap::iterator it = active_topics.find(clientid);
        if (it != active_topics.end()) {
            TopicList& topics = it->second;
            for (TopicList::iterator t = topics.begin(); t != topics.end(); ++t) {
                AJ_InfoPrintf(("removing %s due to lost presence\n", t->c_str()));
                mosquitto_publish(mosq, NULL, t->c_str(), 0, NULL, 0, TRUE);
                mosquitto_loop_write(mosq, 1);
            }

            active_topics.erase(it);
        }
    } else if (id == "1") {
        ClientIds::iterator lit = clients.find(client);
        if (lit != clients.end()) {
            IdList& ids = lit->second;

            for (IdList::iterator idit = ids.begin(); idit != ids.end(); ++idit) {
                std::pair<std::string, std::string> clientid = std::make_pair(client, *idit);
                SenderTopicMap::iterator it = active_topics.find(clientid);

                if (it != active_topics.end()) {
                    TopicList& topics = it->second;
                    for (TopicList::iterator t = topics.begin(); t != topics.end(); ++t) {
                        AJ_InfoPrintf(("removing %s due to lost presence\n", t->c_str()));
                        mosquitto_publish(mosq, NULL, t->c_str(), 0, NULL, 0, TRUE);
                        mosquitto_loop_write(mosq, 1);
                    }

                    active_topics.erase(it);
                }
            }

            clients.erase(lit);
        }
    } else {
        ClientIds::iterator lit = clients.find(client);
        if (lit != clients.end()) {
            IdList& ids = lit->second;

            IdList::iterator idit = ids.find(id);
            if (idit != ids.end()) {
                ids.erase(idit);
            }

            std::pair<std::string, std::string> clientid = std::make_pair(client, id);
            SenderTopicMap::iterator it = active_topics.find(clientid);
            if (it != active_topics.end()) {
                TopicList& topics = it->second;
                for (TopicList::iterator t = topics.begin(); t != topics.end(); ++t) {
                    AJ_InfoPrintf(("removing %s due to lost presence\n", t->c_str()));
                    mosquitto_publish(mosq, NULL, t->c_str(), 0, NULL, 0, TRUE);
                    mosquitto_loop_write(mosq, 1);
                }

                active_topics.erase(it);
            }

            clients.erase(lit);
        }
    }
}

static void HandleClientAdded(const std::string& client, std::string& id)
{
    AJ_InfoPrintf(("HandleClientAdded: client=%s, id=%s\n", client.c_str(), id.c_str()));

    if (id != "0" && id != "1") {
        clients[client].insert(id);
    }

    // still present; subscribe to this member's sessionless signals!
    std::string topic = Scope + '/' + client + '/' + id + "/+/+";
    mosquitto_subscribe(mosq, NULL, topic.c_str(), 0);
    mosquitto_loop_misc(mosq);
}

static void HandleTopicRemoved(const std::string& client, const std::string& topic, const std::string& id)
{
    AJ_InfoPrintf(("HandleTopicRemoved: client=%s, topic=%s\n", client.c_str(), topic.c_str()));

    std::pair<std::string, std::string> clientid = std::make_pair(client, id);
    // 'id' was lost!
    SenderTopicMap::iterator it = active_topics.find(clientid);
    if (it != active_topics.end()) {
        TopicList& topics = it->second;
        TopicList::iterator it2 = topics.find(topic);
        if (it2 != topics.end()) {
            topics.erase(it2);
        }

        if (topics.empty()) {
            active_topics.erase(it);
        }
    }
}

static AJ_Status DUMMY_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    return AJ_OK;
}


static void HandleSessionlessSignal(const struct mosquitto_message* msg, const std::string& client, const std::string& topic, const std::string& id)
{
    AJ_InfoPrintf(("Got sessionless signal from %s\n", topic.c_str()));

    std::pair<std::string, std::string> clientid = std::make_pair(client, id);

    active_topics[clientid].insert(topic);
    uint32_t ttl = 0;

    AJ_BusAttachment bus;
    memset(&bus, 0, sizeof(AJ_BusAttachment));

    bus.sock.rx.recv = DUMMY_Recv;
    bus.sock.rx.direction = AJ_IO_BUF_RX;

    bus.sock.rx.bufStart = bus.sock.rx.readPtr = (uint8_t*) msg->payload;

    bus.sock.rx.writePtr = bus.sock.rx.readPtr + msg->payloadlen;
    bus.sock.rx.bufSize = msg->payloadlen;


    AJ_Message message;

    AJ_Status status = AJ_UnmarshalMsg(&bus, &message, 0xFFFFFFFF);
    if (status == AJ_OK) {
        ttl = message.ttl;
    }

    if (ttl != 0) {
        AJ_Time now;
        AJ_InitTimer(&now);
        time_t when = now.seconds + ttl;

        Timeout timeout;
        timeout.id = id;
        timeout.topic = topic;
        timeout.client = client;

        timeouts.insert(std::make_pair(when, timeout));
    }
}


static void OnMessageRecv(struct mosquitto* mosq, void* ctx, const struct mosquitto_message* msg)
{
    bool result;
    int ret;

    AJ_InfoPrintf(("OnMessageRecv(): received %d bytes topic \"%s\"\n", msg->payloadlen, msg->topic));

    /*
     * Check for presence publication
     */
    ret = mosquitto_topic_matches_sub("+/presence/+/+", msg->topic, &result);
    if (result == TRUE) {
        std::string topic = msg->topic;

        size_t s1 = topic.find_first_of('/');
        assert(s1 != std::string::npos);
        s1 = topic.find_first_of('/', s1 + 1);
        assert(s1 != std::string::npos);

        size_t s2 = topic.find_first_of('/', s1 + 1);
        assert(s2 != std::string::npos);
        std::string client = topic.substr(s1 + 1, s2 - s1 - 1);

        // the ID will be at the end of the string
        std::string id = topic.substr(s2 + 1);

        if (msg->payloadlen == 0) {
            // no longer present; clear everything out that belongs to this member!
            HandleClientRemoved(client, id);
        } else {
            HandleClientAdded(client, id);
        }

        return;
    }

    // topic: scope/client/id/iface/member
    // need to extract the client and id
    std::string topic = msg->topic;
    size_t s1 = topic.find_first_of('/');
    assert(s1 != std::string::npos);

    size_t s2 = topic.find_first_of('/', s1 + 1);
    assert(s2 != std::string::npos);
    std::string client = topic.substr(s1 + 1, s2 - s1 - 1);

    size_t s3 = topic.find_first_of('/', s2 + 1);
    assert(s3 != std::string::npos);
    std::string id = topic.substr(s2 + 1, s3 - s2 - 1);

    if (msg->payloadlen == 0) {
        HandleTopicRemoved(client, topic, id);
    } else {
        /* else we need to parse the message's header to determine:
         *
         * 1) is this a sesssionless signal?  If not we don't care about it.
         * 2) what is the TTL?
         * 3) who owns it?
         */

        const uint8_t flags = ((uint8_t*) msg->payload)[2];
        if (flags & AJ_FLAG_SESSIONLESS) {
            HandleSessionlessSignal(msg, client, topic, id);
        }
    }
}

int main(int argc, char** argv)
{
    int opt;
    int port = 1883;
    const char* host = "127.0.0.1";

    while ((opt = getopt(argc, argv, "s:h:p:")) != -1) {
        switch (opt) {
        case 's':
            Scope = optarg;
            break;

        case 'h':
            host = optarg;
            break;

        case 'p':
            port = strtol(optarg, NULL, 10);
            break;

        default:
            fprintf(stderr, "Usage: %s [-s scope] \n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    mosquitto_lib_init();
    mosq = mosquitto_new("scavenger", TRUE, NULL);


    int ret = mosquitto_connect(mosq, host, port, 60);
    if (ret != MOSQ_ERR_SUCCESS) {
        return EXIT_FAILURE;
    }

    mosquitto_max_inflight_messages_set(mosq, 0);
    mosquitto_message_callback_set(mosq, OnMessageRecv);

    std::string topic = Scope + "/presence/+/+";
    mosquitto_subscribe(mosq, NULL, topic.c_str(), 0);
    mosquitto_loop_misc(mosq);


    int sock = mosquitto_socket(mosq);

    while (TRUE) {
        uint32_t blocktime = HandleTimeouts();
        struct timeval tv = { blocktime / 1000, 1000 * (blocktime % 1000) };
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        int rc = select(sock + 1, &fds, NULL, NULL, &tv);

        if (rc == 0) {
            mosquitto_loop_misc(mosq);
            continue;
        }

        ret = mosquitto_loop_read(mosq, 1);

        if (mosquitto_want_write(mosq)) {
            ret = mosquitto_loop_write(mosq, 1);
        }
    }

    mosquitto_unsubscribe(mosq, NULL, topic.c_str());
    mosquitto_loop_misc(mosq);

    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    return 0;
}
