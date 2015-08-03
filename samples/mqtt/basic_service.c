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

static const char ServicePath[] = "/sample";

uint8_t dbgSAMPLE = 0;

/**
 * The interface name followed by the method signatures.
 *
 * See also .\inc\aj_introspect.h
 */
static const char* const sampleInterface[] = {
    "com.example.sample",              /* The first entry is the interface name. */
    "?cat inStr1<s inStr2<s outStr>s", /* Method at index 0. */
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
 * Objects implemented by the application. The first member in the AJ_Object structure is the path.
 * The second is the collection of all interfaces at that path.
 */
static const AJ_Object AppObjects[] = {
    { ServicePath, sampleInterfaces, AJ_OBJ_FLAG_ANNOUNCED },
    { NULL }
};

#define BASIC_SERVICE_CAT AJ_APP_MESSAGE_ID(0, 0, 0)

static AJ_Status AppHandleCat(AJ_Message* msg)
{
#define BUFFER_SIZE 256
    const char* string0;
    const char* string1;
    char buffer[BUFFER_SIZE];
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "ss", &string0, &string1);
    AJ_MarshalReplyMsg(msg, &reply);

    /* We have the arguments. Now do the concatenation. */
    strncpy(buffer, string0, BUFFER_SIZE);
    buffer[BUFFER_SIZE - 1] = '\0';
    strncat(buffer, string1, BUFFER_SIZE - strlen(buffer));
    buffer[BUFFER_SIZE - 1] = '\0';

    AJ_InitArg(&replyArg, AJ_ARG_STRING, 0, buffer, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);

#undef BUFFER_SIZE
}

/* All times are expressed in milliseconds. */
#define CONNECT_TIMEOUT     (1000 * 60)
#define UNMARSHAL_TIMEOUT   (1000 * 5)
#define SLEEP_TIME          (1000 * 2)

#define PORT 16

static AJ_SessionOpts sessionOpts = {
    AJ_SESSION_TRAFFIC_MESSAGES,
    AJ_SESSION_PROXIMITY_ANY,
    AJ_TRANSPORT_ANY,
    TRUE                          /* is multipoint */
};

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
            connected = TRUE;
            AJ_AboutInit(&bus, PORT);
            AJ_BusBindSessionPort(&bus, PORT, &sessionOpts, 0);
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }
        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_METHOD_ACCEPT_SESSION:
                AJ_AlwaysPrintf(("Accepting session joiner\n"));
                status = AJ_BusReplyAcceptSession(&msg, TRUE);
                break;

            case BASIC_SERVICE_CAT:
                status = AppHandleCat(&msg);
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
            AJ_AlwaysPrintf(("AllJoyn disconnect.\n"));
            AJ_Disconnect(&bus);
            connected = FALSE;

            /* Sleep a little while before trying to reconnect. */
            AJ_Sleep(SLEEP_TIME);
        }
    }

    AJ_AlwaysPrintf(("Basic service exiting with status %d.\n", status));

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
