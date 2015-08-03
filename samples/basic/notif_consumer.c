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
#define AJ_MODULE SAMPLE

#include <stdio.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_nvram.h>

uint8_t dbgSAMPLE = 0;

#define HASH_TAB_LEN 600

typedef struct _NotifTracker {
    uint32_t num;
    struct _NotifTracker* next;
    char id[1];
} NotifTracker;

static NotifTracker* hashTable[HASH_TAB_LEN];

static uint32_t Hash(const char* id)
{
    uint32_t hash = HASH_TAB_LEN / 2;
    /*
     * Unique names are random strings so we don't need to do anything clever.
     * We can skip the first character because it is always ':'
     */
    while (*id++) {
        hash += *id;
        hash = (hash << 5) | (hash >> 27); // ROTL5
    }
    return hash % HASH_TAB_LEN;
}

static void NotifCheck(const char* id, uint32_t num)
{
    NotifTracker* tracker;
    uint32_t bucket = Hash(id);

    for (tracker = hashTable[bucket]; tracker != NULL; tracker = tracker->next) {
        if (strcmp(tracker->id, id) == 0) {
            break;
        }
    }
    if (tracker) {
        if (tracker->num != num) {
            if (num > tracker->num) {
                AJ_AlwaysPrintf(("Notification %u is missing\n", tracker->num));
            } else {
                AJ_AlwaysPrintf(("Expected Notification %u got %u\n", tracker->num, num));
            }
        }
    } else {
        size_t len = strlen(id);
        tracker = malloc(sizeof(NotifTracker) + len);
        if (!tracker) {
            AJ_AlwaysPrintf(("malloc failed - exiting\n"));
            exit(1);
        }
        AJ_AlwaysPrintf(("Allocated notification tracker for \"%s\"\n", id));
        memset(tracker, 0, sizeof(NotifTracker));
        memcpy(&tracker->id, id, len + 1);
        tracker->next = hashTable[bucket];
        hashTable[bucket] = tracker;
    }
    tracker->num = num + 1;
}

static const uint16_t NotificationVersion = 2;
static const char NotificationInterfaceName[]   = "org.alljoyn.Notification";

static const char* NotificationInterface[] = {
    NotificationInterfaceName,
    "!&notify >q >i >q >s >s >ay >s >a{iv} >a{ss} >a(ss)",
    "@Version>q",
    NULL
};

/**
 * A NULL terminated collection of all interfaces.
 */
const AJ_InterfaceDescription NotificationInterfaces[] = {
    NotificationInterface,
    NULL
};

/**
 * Registration for the notification interface
 */
static const AJ_Object AppObjects[] = {
    { "!", NotificationInterfaces },
    { NULL }
};

#define NOTIF_SIGNAL_ID AJ_APP_MESSAGE_ID(0, 0, 0)

/* All times are expressed in milliseconds. */
#define CONNECT_TIMEOUT     (1000 * 60)
#define UNMARSHAL_TIMEOUT   (1000 * 5)
#define SLEEP_TIME          (1000 * 2)

#define PORT 16

static AJ_Status ParseNotification(AJ_Message* notif)
{
    const char* TYPES[] = { "Emergency", "Warning", "Informational", "Unknown" };
    AJ_Status status;
    uint16_t version;
    uint32_t id;
    uint16_t notifType;
    const char* devId;
    const char* devName;
    const uint8_t* appId;
    size_t appIdLen;
    const char* appName;
    AJ_Arg strings;

    status = AJ_UnmarshalArgs(notif, "qiqssays", &version, &id, &notifType, &devId, &devName, &appIdLen, &appId, &appName);
    notifType = min(notifType, ArraySize(TYPES) - 1);
    /*
     * Ignore the attributes
     */
    if (status == AJ_OK) {
        status = AJ_SkipArg(notif);
    }
    /*
     * Ignore the custom strings
     */
    if (status == AJ_OK) {
        status = AJ_SkipArg(notif);
    }
    if (status == AJ_OK) {
        status = AJ_UnmarshalContainer(notif, &strings, AJ_ARG_ARRAY);
    }
    while (status == AJ_OK) {
        const char* lang;
        const char* text;
        status = AJ_UnmarshalArgs(notif, "(ss)", &lang, &text);
        if (status != AJ_OK) {
            break;
        }
        //AJ_AlwaysPrintf(("%s Notification from %s [%s]=\"%s\"\n", TYPES[notifType], devName, lang, text));
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_UnmarshalCloseContainer(notif, &strings);
    }

    NotifCheck(notif->sender, id);

    return status;
}

static const char matchRule[] = "type='signal',interface='org.alljoyn.Notification',member='notify',sessionless='t'";

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;

    /* One time initialization before calling any other AllJoyn APIs. */
    AJ_Initialize();

    /* This is for debug purposes and is optional. */
    AJ_PrintXML(AppObjects);

    AJ_RegisterObjects(AppObjects, NULL);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_FindBusAndConnect(&bus, NULL, AJ_CONNECT_TIMEOUT);
            if (status != AJ_OK) {
                AJ_WarnPrintf(("AJ_FindBusAndConnect(): failed - sleeping for %d seconds\n", AJ_CONNECT_PAUSE / 1000));
                AJ_Sleep(AJ_CONNECT_PAUSE);
                continue;
            }
            /*
             * Register the match rule for receiving notification signals
             */
            status = AJ_BusSetSignalRuleFlags(&bus, matchRule, AJ_BUS_SIGNAL_ALLOW, AJ_FLAG_NO_REPLY_EXPECTED);
            if (status != AJ_OK) {
                AJ_ErrPrintf(("Failed not set Notification Interface AddMatch\n"));
                return status;
            }
            connected = TRUE;
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }
        if (AJ_OK == status) {
            switch (msg.msgId) {
            case NOTIF_SIGNAL_ID:
                status = ParseNotification(&msg);
                break;

            default:
                /* Pass to the built-in handlers. */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }

        /* Messages MUST be discarded to free resources. */
        AJ_CloseMsg(&msg);

        if (status == AJ_ERR_READ) {
            AJ_AlwaysPrintf(("AllJoyn disconnect.\n"));
            AJ_Disconnect(&bus);
            connected = FALSE;

            /* Sleep a little while before trying to reconnect. */
            AJ_Sleep(SLEEP_TIME);
        }
    }

    AJ_AlwaysPrintf(("Notification consumer exiting with status %d.\n", status));

    return status;
}

#ifdef AJ_MAIN
int main(int argc, char* argv[])
{
    int argn = 1;
    while (argn < argc) {
        if (strcmp(argv[argn], "--nvram-file") == 0) {
            if (++argn >= argc) {
                return 1;
            }
            AJ_SetNVRAM_FilePath(argv[argn++]);
            continue;
        }
        ++argn;
    }
    return AJ_Main();
}
#endif

