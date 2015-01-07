/*
 * @file
 */

/******************************************************************************
 * Copyright (c) 2012-2015, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE SECURE_CLIENT

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "alljoyn.h"
#include "aj_debug.h"
#include "aj_crypto.h"
#include "aj_crypto_ecc.h"
#include "aj_creds.h"
#include "aj_cert.h"
#include "aj_peer.h"
#include "aj_auth_listener.h"
#include "aj_util.h"

uint8_t dbgSECURE_CLIENT = 0;

/*
 * Default key expiration
 */
static const uint32_t keyexpiration = 0xFFFFFFFF;

static const char ServiceName[] = "org.alljoyn.bus.samples.secure";
static const char InterfaceName[] = "org.alljoyn.bus.samples.secure.SecureInterface";
static const char ServicePath[] = "/SecureService";
static const uint16_t ServicePort = 42;

static const char* const secureInterface[] = {
    "$org.alljoyn.bus.samples.secure.SecureInterface",
    "?Ping inStr<s outStr>s",
    NULL
};

static const AJ_InterfaceDescription secureInterfaces[] = {
    secureInterface,
    NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object ProxyObjects[] = {
    { ServicePath, secureInterfaces },
    { NULL }
};

#define PRX_PING   AJ_PRX_MESSAGE_ID(0, 0, 0)

/*
 * Let the application do some work
 */
static void AppDoWork()
{
}

/*
 * get a line of input from the file pointer (most likely stdin).
 * This will capture the the num-1 characters or till a newline character is
 * entered.
 *
 * @param[out] str a pointer to a character array that will hold the user input
 * @param[in]  num the size of the character array 'str'
 * @param[in]  fp the file pointer the sting will be read from. (most likely stdin)
 *
 * @return returns the length of the string received from the file.
 */
uint32_t get_line(char*str, int num, FILE*fp)
{
    uint32_t stringLength = 0;
    char*p = fgets(str, num, fp);

    // fgets will capture the '\n' character if the string entered is shorter than
    // num. Remove the '\n' from the end of the line and replace it with nul '\0'.
    if (p != NULL) {
        stringLength = (uint32_t)strlen(str) - 1;
        if (str[stringLength] == '\n') {
            str[stringLength] = '\0';
        }
    }

    return stringLength;
}

#define CONNECT_TIMEOUT    (1000 * 200)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (100 * 10)

static char pingString[] = "Client AllJoyn Lite says Hello AllJoyn!";

AJ_Status SendPing(AJ_BusAttachment* bus, uint32_t sessionId)
{
    AJ_Status status;
    AJ_Message msg;

    AJ_Printf("Sending ping request '%s'.\n", pingString);

    status = AJ_MarshalMethodCall(bus,
                                  &msg,
                                  PRX_PING,
                                  ServiceName,
                                  sessionId,
                                  AJ_FLAG_ENCRYPTED,
                                  METHOD_TIMEOUT);
    if (AJ_OK == status) {
        status = AJ_MarshalArgs(&msg, "s", pingString);
    } else {
        AJ_InfoPrintf(("In SendPing() AJ_MarshalMethodCall() status = %d.\n", status));
    }

    if (AJ_OK == status) {
        status = AJ_DeliverMsg(&msg);
    } else {
        AJ_InfoPrintf(("In SendPing() AJ_MarshalArgs() status = %d.\n", status));
    }

    if (AJ_OK != status) {
        AJ_InfoPrintf(("In SendPing() AJ_DeliverMsg() status = %d.\n", status));
    }

    return status;
}

//static const char psk_b64[] = "EBESExQVFhcYGRobHB0eHw==";
//static uint8_t psk[16];
static const char psk_hint[] = "bob";
static const char psk_char[] = "123456";

static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;
    AJ_Printf("AuthListenerCallback authmechanism %d command %d\n", authmechanism, command);

    switch (authmechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = keyexpiration;
        status = AJ_OK;
        break;

    case AUTH_SUITE_ECDHE_PSK:
        switch (command) {
        case AJ_CRED_PUB_KEY:
            break; // Don't use username - use anon
            cred->mask = AJ_CRED_PUB_KEY;
            cred->data = (uint8_t*) psk_hint;
            cred->len = strlen(psk_hint);
            status = AJ_OK;
            break;

        case AJ_CRED_PRV_KEY:
            if (AJ_CRED_PUB_KEY == cred->mask) {
                AJ_Printf("Request Credentials for PSK ID: %s\n", cred->data);
            }
            cred->mask = AJ_CRED_PRV_KEY;
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

int AJ_Main(int ac, char** av)
{
    int done = FALSE;
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;
    AJ_Status authStatus = AJ_ERR_NULL;

    uint32_t suites[16];
    size_t numsuites = 0;
    uint8_t clearkeys = FALSE;

    ac--;
    av++;
    /*
     * Enable authentication mechanism by command line
     */
    if (ac) {
        if (0 == strncmp(*av, "-ek", 3)) {
            clearkeys = TRUE;
            ac--;
            av++;
        } else if (0 == strncmp(*av, "-e", 2)) {
            ac--;
            av++;
        } else {
            AJ_Printf("SecureClientECDHE [-e|-ek] <encryption suite>\n"
                      "-e <encryption suite>\n"
                      "   Specify an encryption suite to use: ECDHE_ECDSA, ECDHE_PSK, or ECDHE_NULL\n"
                      "   -e can be specified multiple times to support multiple encryption suites\n"
                      "-ek <encryption suite>\n"
                      "    Same as -e, except that any existing authentication keys are cleared. This \n"
                      "    will ensure a new key exchange/password validation occurs\n");
            return AJ_ERR_NULL;
        }
        if (!ac) {
            AJ_Printf("-e(k) requires an auth mechanism.\n");
            return 1;
        }
        while (ac) {
            if (0 == strncmp(*av, "ECDHE_ECDSA", 11)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
            } else if (0 == strncmp(*av, "ECDHE_PSK", 9)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
            } else if (0 == strncmp(*av, "ECDHE_NULL", 10)) {
                suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
            }
            ac--;
            av++;
        }
    }

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(ProxyObjects);
    AJ_RegisterObjects(NULL, ProxyObjects);

    while (!done) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartClient(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServiceName, ServicePort, &sessionId, NULL);
            if (status == AJ_OK) {
                AJ_InfoPrintf(("StartClient returned %d, sessionId=%u\n", status, sessionId));
                AJ_Printf("StartClient returned %d, sessionId=%u\n", status, sessionId);
                connected = TRUE;
                AJ_BusEnableSecurity(&bus, suites, numsuites);
                AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
                if (clearkeys) {
                    status = AJ_ClearCredentials(AJ_CRED_TYPE_GENERIC);
                    AJ_ASSERT(AJ_OK == status);
                }

                status = AJ_BusAuthenticatePeer(&bus, ServiceName, AuthCallback, &authStatus);
                if (status != AJ_OK) {
                    AJ_Printf("AJ_BusAuthenticatePeer returned %d\n", status);
                    break;
                }
            } else {
                AJ_InfoPrintf(("StartClient returned %d\n", status));
                AJ_Printf("StartClient returned %d\n", status);
                break;
            }
        }

        if (authStatus != AJ_ERR_NULL) {
            if (authStatus != AJ_OK) {
                AJ_Disconnect(&bus);
                break;
            }
            authStatus = AJ_ERR_NULL;
            status = SendPing(&bus, sessionId);
            if (status != AJ_OK) {
                AJ_Printf("SendPing returned %d\n", status);
                continue;
            }
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            AppDoWork();
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_REPLY_ID(PRX_PING):
                {
                    AJ_Arg arg;

                    if (AJ_OK == AJ_UnmarshalArg(&msg, &arg)) {
                        AJ_Printf("%s.Ping (path=%s) returned \"%s\".\n", InterfaceName,
                                  ServicePath, arg.val.v_string);

                        if (strcmp(arg.val.v_string, pingString) == 0) {
                            AJ_InfoPrintf(("Ping was successful.\n"));
                        } else {
                            AJ_InfoPrintf(("Ping returned different string.\n"));
                        }
                    } else {
                        AJ_ErrPrintf(("Bad ping response.\n"));
                    }
                    done = TRUE;
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /*
                 * Force a disconnect
                 */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u", id, reason));
                }
                status = AJ_ERR_SESSION_LOST;
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

        if (status == AJ_ERR_READ) {
            AJ_Printf("AllJoyn disconnect.\n");
            AJ_Disconnect(&bus);
            exit(0);
        }
    }

    AJ_Printf("SecureClient EXIT %d.\n", status);

    return status;
}

#ifdef AJ_MAIN
int main(int argc, char** argv)
{
    return AJ_Main(argc, argv);
}

#endif
