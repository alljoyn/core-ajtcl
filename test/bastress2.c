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

#include <ajtcl/aj_target.h>
#include <ajtcl/alljoyn.h>


#define CONNECT_TIMEOUT    (1000ul * 200)
#define UNMARSHAL_TIMEOUT  (1000ul * 5)
#define METHOD_TIMEOUT     (1000ul * 3)

/// globals
uint8_t connected = FALSE;
uint32_t sessionId = 0ul;
AJ_Status authStatus = AJ_ERR_NULL;

static const char ServiceName[] = "org.alljoyn.Bus.test.bastress";
static const uint16_t ServicePort = 25;
static uint32_t authenticate = TRUE;

static const char* const testInterface[] = {
    "org.alljoyn.Bus.test.bastress",
    "?cat inStr1<s inStr2<s outStr>s",
    NULL
};


static const AJ_InterfaceDescription testInterfaces[] = {
    testInterface,
    NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object AppObjects[] = {
    { "/sample", testInterfaces },
    { NULL }
};

#define APP_MY_CAT  AJ_APP_MESSAGE_ID(0, 0, 0)


/*
 * Let the application do some work
 */
void AppDoWork()
{
    AJ_AlwaysPrintf(("AppDoWork\n"));
}

static const char psk_hint[] = "<anonymous>";
/*
 * The tests were changed at some point to make the psk longer.
 * If doing backcompatibility testing with previous versions (14.06 or before),
 * define LITE_TEST_BACKCOMPAT to use the old version of the password.
 */
#ifndef LITE_TEST_BACKCOMPAT
static const char psk_char[] = "faaa0af3dd3f1e0379da046a3ab6ca44";
#else
static const char psk_char[] = "1234";
#endif

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_AlwaysPrintf(("AuthListenerCallback authmechanism %08X command %d\n", authmechanism, command));

    switch (authmechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = keyexpiration;
        status = AJ_OK;
        break;

    case AUTH_SUITE_ECDHE_PSK:
        switch (command) {
        case AJ_CRED_PUB_KEY:
            cred->data = (uint8_t*) psk_hint;
            cred->len = strlen(psk_hint);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;

        case AJ_CRED_PRV_KEY:
            cred->data = (uint8_t*) psk_char;
            cred->len = strlen(psk_char);
            cred->expiration = keyexpiration;
            status = AJ_OK;
            break;
        }
        break;

    default:
        break;
    }
    return status;
}

void AuthCallback(const void* context, AJ_Status status)
{
    *((AJ_Status*)context) = status;
}

AJ_Status AppHandleCat(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    AJ_Message reply;
    char* partA;
    char* partB;
    char* totalString;
    AJ_AlwaysPrintf(("%s:%d:%s %d\n", __FILE__, __LINE__, __FUNCTION__, 0));

    AJ_UnmarshalArgs(msg, "ss", &partA, &partB);

    totalString = (char*) AJ_Malloc(strlen(partA) + strlen(partB) + 1);
    if (!totalString) {
        return AJ_ERR_RESOURCES;
    }
    strcpy(totalString, partA);
    strcpy(totalString + strlen(partA), partB);

    AJ_MarshalReplyMsg(msg, &reply);
    AJ_MarshalArgs(&reply, "s", totalString);

    status = AJ_DeliverMsg(&reply);
    AJ_Free(totalString);
    return status;
}

int AJ_Main()
{
    AJ_Status status;
    AJ_BusAttachment bus;
    // you're connected now, so print out the data:
    AJ_AlwaysPrintf(("You're connected to the network\n"));
    AJ_Initialize();
    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartService(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServicePort, ServiceName, AJ_NAME_REQ_DO_NOT_QUEUE, NULL);
            if (status == AJ_OK) {
                AJ_AlwaysPrintf(("StartService returned %d\n", status));
                connected = TRUE;
                if (authenticate) {
                    AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
                } else {
                    authStatus = AJ_OK;
                }
            } else {
                AJ_AlwaysPrintf(("StartClient returned %d\n", status));
                continue;
            }
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                AppDoWork();
                continue;
            }
        }

        if (status == AJ_OK) {
            switch (msg.msgId) {

            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    AJ_AlwaysPrintf(("Accepting...\n"));
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    status = AJ_BusReplyAcceptSession(&msg, TRUE);
                    if (status == AJ_OK) {
                        AJ_AlwaysPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
                    } else {
                        AJ_AlwaysPrintf(("AJ_BusReplyAcceptSession: error %d\n", status));
                    }
                }
                break;

            case APP_MY_CAT:
                status = AppHandleCat(&msg);
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /*
                 * don't force a disconnect, be ready to accept another session
                 */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %d", id, reason));
                }
                break;

            default:
                /*
                 * Pass to the built-in handlers
                 */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }
        /*
         * Messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_READ) || (status == AJ_ERR_LINK_DEAD)) {
            AJ_AlwaysPrintf(("AllJoyn disconnect\n"));
            AJ_Disconnect(&bus);
            connected = FALSE;
            /*
             * Sleep a little while before trying to reconnect
             */
            AJ_Sleep(10 * 1000);
        }
    }

    return 0;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
