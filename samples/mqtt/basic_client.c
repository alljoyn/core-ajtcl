/*
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
#include <stdlib.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_nvram.h>

uint8_t dbgSAMPLE = 0;

/**
 * The interface name followed by the method signatures.
 */
static const char* const sampleInterface[] = {
    "com.example.sample",              /* The first entry is the interface name. */
    "?cat inStr1<s inStr2<s outStr>s", /* Method at index 2. */
    NULL
};

/**
 * A NULL terminated collection of all interfaces.
 */
static const AJ_InterfaceDescription sampleInterfaces[] = {
    sampleInterface,
    NULL
};

/**
 * Proxies for interfaces called by this application
 */
static AJ_Object proxyObjects[] = {
    { "*", sampleInterfaces },
    { NULL }
};

#define BASIC_CLIENT_CAT AJ_PRX_MESSAGE_ID(0, 0, 0)

#define CONNECT_TIMEOUT    (1000 * 60)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (100 * 10)

static const char* peerInterfaces[] = { "com.example.sample" };

static uint8_t OnAboutMatch(uint16_t version, uint16_t port, const char* peerName, const char* objPath);
static uint8_t IsRelevant(const char* sender);

/*
 * Needs to be global because of current deficiency in ANNOUNCE_BASED_DISCOVERY APIs.
 */
static AJ_BusAttachment bus;

static AJ_AboutPeerDescription peerDescriptions[] = { { peerInterfaces, ArraySize(peerInterfaces), OnAboutMatch, IsRelevant } };

char serviceObjPath[64];
char serviceName[64];
uint32_t sessionId = 0;

static uint8_t IsRelevant(const char* sender)
{
    /*
     * Ignore our own announcements
     */
    return !sessionId && (strcmp(sender, AJ_GetUniqueName(&bus)) != 0);
}

static uint8_t OnAboutMatch(uint16_t version, uint16_t port, const char* peerName, const char* objPath)
{
    AJ_Status status;

    strncpy(serviceObjPath, objPath, sizeof(serviceObjPath));
    serviceObjPath[sizeof(serviceObjPath) - 1] = 0;

    strncpy(serviceName, peerName, sizeof(serviceName));
    serviceName[sizeof(serviceName) - 1] = 0;

    status = AJ_BusJoinSession(&bus, peerName, port, NULL);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("JoinSession failed %s\n", AJ_StatusText(status)));
    }

    return TRUE;
}

static void DoCat()
{
    AJ_Status status;
    AJ_Message msg;

    /*
     * Set the object path so we can make a method call
     */
    (void)AJ_SetProxyObjectPath(proxyObjects, BASIC_CLIENT_CAT, serviceObjPath);

    status = AJ_MarshalMethodCall(&bus, &msg, BASIC_CLIENT_CAT, serviceName, sessionId, 0, METHOD_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "ss", "Hello ", "World!");
    }
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    AJ_InfoPrintf(("MakeMethodCall() resulted in a status of 0x%04x.\n", status));
}

static uint8_t waitVar = FALSE;

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    uint8_t connected = FALSE;
    uint8_t done = FALSE;

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();
    AJ_RegisterObjects(NULL, proxyObjects);

    while (!done) {
        AJ_Message msg;

        if (!connected) {
            const char* announceRule = "type='signal',sessionless='t',interface='org.alljoyn.About',member='Announce'";
            status = AJ_FindBusAndConnect(&bus, NULL, AJ_CONNECT_TIMEOUT);
            if (status != AJ_OK) {
                AJ_WarnPrintf(("AJ_FindBusAndConnect(): failed - sleeping for %d seconds\n", AJ_CONNECT_PAUSE / 1000));
                AJ_Sleep(AJ_CONNECT_PAUSE);
                continue;
            }
            AJ_AboutRegisterAnnounceHandlers(peerDescriptions, ArraySize(peerDescriptions));
            AJ_BusSetSignalRule(&bus, announceRule, AJ_BUS_SIGNAL_ALLOW);
            connected = TRUE;
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION):
                if (msg.hdr->msgType != AJ_MSG_ERROR) {
                    uint32_t result;

                    status = AJ_UnmarshalArgs(&msg, "uu", &result, &sessionId);
                    if (status == AJ_OK) {
                        if (result == AJ_JOINSESSION_REPLY_SUCCESS) {
                            AJ_AlwaysPrintf(("joined session %u\n", sessionId));
                            DoCat();
                        } else {
                            AJ_AlwaysPrintf(("joined session rejected %d\n", result));
                        }
                    }
                } else {
                    AJ_ErrPrintf(("JoinSession reply was error: %s\n", msg.error));
                }
                break;

            case AJ_REPLY_ID(BASIC_CLIENT_CAT):
                if (msg.hdr->msgType != AJ_MSG_ERROR) {
                    AJ_Arg arg;
                    status = AJ_UnmarshalArg(&msg, &arg);
                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("cat returned \"%s\"\n", arg.val.v_string));
                        if (!waitVar) {
                            done = TRUE;
                        }
                    }
                } else {
                    AJ_ErrPrintf(("Reply was error: %s\n", msg.error));
                }
                break;

            case AJ_SIGNAL_MP_SESSION_CHANGED_WITH_REASON:
                {
                    uint32_t sessId;
                    const char* peer;
                    uint32_t added;
                    uint32_t reason;

                    status = AJ_UnmarshalArgs(&msg, "usbu", &sessId, &peer, &added, &reason);
                    if (added) {
                        AJ_AlwaysPrintf(("Member \"%s\" added to session %u\n", peer, sessId));
                    } else {
                        AJ_AlwaysPrintf(("Member \"%s\" removed from session %u\n", peer, sessId));
                    }
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                AJ_AlwaysPrintf(("Session lost\n"));
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
            AJ_AlwaysPrintf(("Connection lost\n"));
            AJ_Disconnect(&bus);
            exit(0);
        }
    }
    AJ_AlwaysPrintf(("Basic client exiting with status %d.\n", status));
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
        if (strcmp(argv[argn], "--wait") == 0) {
            ++argn;
            waitVar = TRUE;
        }
        ++argn;
    }
    return AJ_Main();
}
#endif
