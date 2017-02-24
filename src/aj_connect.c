/**
 * @file
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
 *    
 *    SPDX-License-Identifier: Apache-2.0
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *    
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *    
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
******************************************************************************/


#include "aj_target.h"
#include "aj_status.h"
#include "aj_bufio.h"
#include "aj_msg.h"
#include "aj_connect.h"
#include "aj_introspect.h"
#include "aj_sasl.h"
#include "aj_net.h"
#include "aj_debug.h"
#include "aj_bus.h"
#include "aj_disco.h"
#include "aj_std.h"
#include "aj_auth.h"

/*
 * For testing on host  set this value to 1 to bypass the discovery and connect directly to port
 * 9955 on daemon on local host.
 */
#define AJ_CONNECT_LOCALHOST  0

static const char daemonService[] = "org.alljoyn.BusNode";

static uint32_t DefaultBusAuthPwdFunc(uint8_t* buffer, uint32_t bufLen)
{
    const char* defaultPwd = "1234";
    strcpy((char*)buffer, defaultPwd);
    return (uint32_t)strlen(defaultPwd);
}

static BusAuthPwdFunc busAuthPwdFunc = DefaultBusAuthPwdFunc;

void SetBusAuthPwdCallback(BusAuthPwdFunc callback)
{
    busAuthPwdFunc = callback;
}

static AJ_AuthResult AnonMechAdvance(const char* inStr, char* outStr, uint32_t outLen)
{
    return AJ_AUTH_STATUS_SUCCESS;
}

static AJ_Status AnonMechInit(uint8_t role, AJ_AuthPwdFunc pwdFunc)
{
    return AJ_OK;
}

static const AJ_AuthMechanism authAnonymous = {
    AnonMechInit,
    AnonMechAdvance,
    AnonMechAdvance,
    NULL,
    "ANONYMOUS"
};

/*
 * Authentication mechanisms in order of preference
 */
static const AJ_AuthMechanism* const mechList[] = { &AJ_AuthPin, &authAnonymous, NULL };

static AJ_Status SendHello(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_HELLO, AJ_DBusDestination, 0, AJ_FLAG_ALLOW_REMOTE_MSG, 5000);
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

static AJ_Status AuthAdvance(AJ_SASL_Context* context, AJ_IOBuffer* rxBuf, AJ_IOBuffer* txBuf)
{
    AJ_Status status = AJ_OK;

    if (context->state != AJ_SASL_SEND_AUTH_REQ) {
        /*
         * All the authentication messages end in a CR/LF so read until we get a newline
         */
        while ((AJ_IO_BUF_AVAIL(rxBuf) == 0) || (*(rxBuf->writePtr - 1) != '\n')) {
            status = rxBuf->recv(rxBuf, AJ_IO_BUF_SPACE(rxBuf), 3500);
            if (status != AJ_OK) {
                break;
            }
        }
    }
    if (status == AJ_OK) {
        uint32_t inLen = AJ_IO_BUF_AVAIL(rxBuf);
        *rxBuf->writePtr = '\0';
        status = AJ_SASL_Advance(context, (char*)rxBuf->readPtr, (char*)txBuf->writePtr, AJ_IO_BUF_SPACE(txBuf));
        if (status == AJ_OK) {
            rxBuf->readPtr += inLen;
            txBuf->writePtr += strlen((char*)txBuf->writePtr);
            status = txBuf->send(txBuf);
        }
    }
    return status;
}

AJ_Status AJ_Connect(AJ_BusAttachment* bus, const char* serviceName, uint32_t timeout)
{
    AJ_Status status;
    AJ_SASL_Context sasl;
    AJ_Service service;
    /*
     * Clear the bus struct
     */
    memset(bus, 0, sizeof(AJ_BusAttachment));
    /*
     * Clear stale name->GUID mappings
     */
    AJ_GUID_ClearNameMap();
    /*
     * Host-specific network bring-up procedure. This includes establishing a connection to the
     * network and initializing the I/O buffers.
     */
    status = AJ_Net_Up();
    if (status != AJ_OK) {
        return status;
    }
    /*
     * Discover a daemon or service to connect to
     */
    if (!serviceName) {
        serviceName = daemonService;
    }
#if AJ_CONNECT_LOCALHOST
    service.ipv4port = 9955;
#if HOST_IS_LITTLE_ENDIAN
    service.ipv4 = 0x0100007F; // 127.0.0.1
#endif
#if HOST_IS_BIG_ENDIAN
    service.ipv4 = 0x7f000001; // 127.0.0.1
#endif
    service.addrTypes = AJ_ADDR_IPV4;
#elif defined ARDUINO
    service.ipv4port = 9955;
    service.ipv4 = 0x6501A8C0; // 192.168.1.101
    service.addrTypes = AJ_ADDR_IPV4;
    status = AJ_Discover(serviceName, &service, timeout);
    if (status != AJ_OK) {
        goto ExitConnect;
    }
#elif defined AJ_SERIAL_CONNECTION
    // don't bother with discovery, we are connected to a daemon.
#else
    status = AJ_Discover(serviceName, &service, timeout);
    if (status != AJ_OK) {
        goto ExitConnect;
    }
#endif
    status = AJ_Net_Connect(&bus->sock, service.ipv4port, service.addrTypes & AJ_ADDR_IPV4, &service.ipv4);
    if (status != AJ_OK) {
        goto ExitConnect;
    }
    /*
     * Send initial NUL byte
     */
    bus->sock.tx.writePtr[0] = 0;
    bus->sock.tx.writePtr += 1;
    status = bus->sock.tx.send(&bus->sock.tx);
    if (status != AJ_OK) {
        goto ExitConnect;
    }
    AJ_SASL_InitContext(&sasl, mechList, AJ_AUTH_RESPONDER, busAuthPwdFunc);
    while (TRUE) {
        status = AuthAdvance(&sasl, &bus->sock.rx, &bus->sock.tx);
        if ((status != AJ_OK) || (sasl.state == AJ_SASL_FAILED)) {
            break;
        }
        if (sasl.state == AJ_SASL_AUTHENTICATED) {
            status = SendHello(bus);
            break;
        }
    }
    if (status == AJ_OK) {
        AJ_Message helloResponse;
        status = AJ_UnmarshalMsg(bus, &helloResponse, 5000);
        if (status == AJ_OK) {
            /*
             * The only error we might get is a timeout
             */
            if (helloResponse.hdr->msgType == AJ_MSG_ERROR) {
                status = AJ_ERR_TIMEOUT;
            } else {
                AJ_Arg arg;
                status = AJ_UnmarshalArg(&helloResponse, &arg);
                if (status == AJ_OK) {
                    if (arg.len >= (sizeof(bus->uniqueName) - 1)) {
                        status = AJ_ERR_RESOURCES;
                    } else {
                        memcpy(bus->uniqueName, arg.val.v_string, arg.len);
                        bus->uniqueName[arg.len] = '\0';
                    }
                }
            }
            AJ_CloseMsg(&helloResponse);

            // subscribe to the signal NameOwnerChanged and wait for the response
            status = AJ_BusSetSignalRule2(bus, "NameOwnerChanged", "org.freedesktop.DBus", AJ_BUS_SIGNAL_ALLOW);

            if (status == AJ_OK) {
                uint8_t found_reply = FALSE;
                AJ_Message msg;
                AJ_Time timer;
                AJ_InitTimer(&timer);

                while (found_reply == FALSE && AJ_GetElapsedTime(&timer, TRUE) < 3000) {
                    status = AJ_UnmarshalMsg(bus, &msg, 3000);
                    if (status == AJ_OK) {
                        switch (msg.msgId) {
                        case AJ_REPLY_ID(AJ_METHOD_ADD_MATCH):
                            found_reply = TRUE;
                            break;

                        default:
                            // ignore everything else
                            AJ_BusHandleBusMessage(&msg);
                            break;
                        }

                        AJ_CloseMsg(&msg);
                    }
                }
            }
        }
    }

ExitConnect:

    if (status != AJ_OK) {
        AJ_Printf("AllJoyn connect failed %d\n", status);
        AJ_Disconnect(bus);
    }
    return status;
}

void AJ_Disconnect(AJ_BusAttachment* bus)
{
    /*
     * We won't be getting any more method replies.
     */
    AJ_ReleaseReplyContexts();
    /*
     * Disconnect the network closing sockets etc.
     */
    AJ_Net_Disconnect(&bus->sock);
    /*
     * Host-specific network shutdown procedure
     */
    AJ_Net_Down();
}