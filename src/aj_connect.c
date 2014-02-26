/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE CONNECT

#include "aj_target.h"
#include "aj_status.h"
#include "aj_bufio.h"
#include "aj_msg.h"
#include "aj_connect.h"
#include "aj_introspect.h"
#include "aj_sasl.h"
#include "aj_net.h"
#include "aj_bus.h"
#include "aj_disco.h"
#include "aj_std.h"
#include "aj_auth.h"
#include "aj_debug.h"
#include "aj_config.h"

#if !(defined(ARDUINO) || defined(__linux) || defined(_WIN32))
#include "aj_wifi_ctrl.h"
#endif

#ifdef AJ_SERIAL_CONNECTION
#include "aj_serial.h"
#endif

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
AJ_EXPORT uint8_t dbgCONNECT = 0;
#endif

static const char daemonService[] = "org.alljoyn.BusNode";

static uint32_t DefaultBusAuthPwdFunc(uint8_t* buffer, uint32_t bufLen)
{
    const char* defaultPwd = "1234";

    AJ_InfoPrintf(("DefaultBusAuthPwdFunc(buffer=0x%p, bufLen=%d.)\n", buffer, bufLen));

    strcpy((char*)buffer, defaultPwd);
    return (uint32_t)strlen(defaultPwd);
}

static BusAuthPwdFunc busAuthPwdFunc = DefaultBusAuthPwdFunc;

void SetBusAuthPwdCallback(BusAuthPwdFunc callback)
{
    AJ_InfoPrintf(("SetBusAuthPwdCallback(callback=0x%p)\n", callback));
    busAuthPwdFunc = callback;
}

static AJ_AuthResult AnonMechAdvance(const char* inStr, char* outStr, uint32_t outLen)
{
    AJ_InfoPrintf(("AnonMechAdvance(instr=\"%s\", outStr=0x%p, outlen=%d.)\n", inStr, outStr, outLen));
    return AJ_AUTH_STATUS_SUCCESS;
}

static AJ_Status AnonMechInit(uint8_t role, AJ_AuthPwdFunc pwdFunc)
{
    AJ_InfoPrintf(("AnonMechInit(role=%d., pwdFunc=0x%p)\n", role, pwdFunc));
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

    AJ_InfoPrintf(("SendHello(bus=0x%p)\n", bus));

    status = AJ_MarshalMethodCall(bus, &msg, AJ_METHOD_HELLO, AJ_DBusDestination, 0, AJ_FLAG_ALLOW_REMOTE_MSG, 5000);
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}

static AJ_Status AuthAdvance(AJ_SASL_Context* context, AJ_IOBuffer* rxBuf, AJ_IOBuffer* txBuf)
{
    AJ_Status status = AJ_OK;

    AJ_InfoPrintf(("AuthAdvance(context=0x%p, rxBuf=0x%p, txBuf=0x%p)\n", context, rxBuf, txBuf));

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

AJ_Status AJ_Authenticate(AJ_BusAttachment* bus)
{
    AJ_Status status = AJ_OK;
    AJ_SASL_Context sasl;

    /*
     * Send initial NUL byte
     */
    bus->sock.tx.writePtr[0] = 0;
    bus->sock.tx.writePtr += 1;
    status = bus->sock.tx.send(&bus->sock.tx);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Authenticate(): status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }
    AJ_SASL_InitContext(&sasl, mechList, AJ_AUTH_RESPONDER, busAuthPwdFunc, FALSE);
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
                        AJ_ErrPrintf(("AJ_Authenticate(): AJ_ERR_RESOURCES\n"));
                        status = AJ_ERR_RESOURCES;
                    } else {
                        memcpy(bus->uniqueName, arg.val.v_string, arg.len);
                        bus->uniqueName[arg.len] = '\0';
                    }
                }
            }
            AJ_CloseMsg(&helloResponse);

            // subscribe to the signal NameOwnerChanged and wait for the response
            status = AJ_BusSetSignalRule(bus, "type='signal',member='NameOwnerChanged',interface='org.freedesktop.DBus'", AJ_BUS_SIGNAL_ALLOW);

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
        AJ_InfoPrintf(("AJ_Authenticate(): status=%s\n", AJ_StatusText(status)));
    }
    return status;
}

#define AJ_DHCP_TIMEOUT  5000

// TODO: deprecate this function; replace it with AJ_FindBusAndConnect
AJ_Status AJ_Connect(AJ_BusAttachment* bus, const char* serviceName, uint32_t timeout)
{
    AJ_Status status;
    AJ_Service service;

#ifdef AJ_SERIAL_CONNECTION
    AJ_Time start, now;
    AJ_InitTimer(&start);
#endif

    AJ_InfoPrintf(("AJ_Connect(bus=0x%p, serviceName=\"%s\", timeout=%d.)\n", bus, serviceName, timeout));

    /*
     * Clear the bus struct
     */
    memset(bus, 0, sizeof(AJ_BusAttachment));
    /*
     * Clear stale name->GUID mappings
     */
    AJ_GUID_ClearNameMap();

#if !(defined(ARDUINO) || defined(__linux) || defined(_WIN32))
    /*
     * Get an IP address.  We don't want to break this older version
     * of AJ_Connect, so acquire an IP if we don't already have one.
     *
     * This does not work on non-embedded platforms!
     */
    {
        uint32_t ip, mask, gw;
        status = AJ_AcquireIPAddress(&ip, &mask, &gw, AJ_DHCP_TIMEOUT);

        if (status != AJ_OK) {
            AJ_ErrPrintf(("AJ_Net_Up(): AJ_AcquireIPAddress Failed\n"));
        }
    }
#endif

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
        AJ_InfoPrintf(("AJ_Connect(): AJ_Discover status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }
#elif defined AJ_SERIAL_CONNECTION
    // don't bother with discovery, we are connected to a daemon.
    // however, take this opportunity to bring up the serial connection
    // in a way that depends on the target
    status = AJ_Serial_Up();
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Serial_Up status=%s\n", AJ_StatusText(status)));
    }
#else
    status = AJ_Discover(serviceName, &service, timeout);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Discover status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }
#endif
    status = AJ_Net_Connect(&bus->sock, service.ipv4port, service.addrTypes & AJ_ADDR_IPV4, &service.ipv4);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Net_Connect status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }

#ifdef AJ_SERIAL_CONNECTION
    // run the state machine for long enough to (hopefully) do the SLAP handshake
    do {
        AJ_StateMachine();
        AJ_InitTimer(&now);
    } while (AJ_SerialLinkParams.linkState != AJ_LINK_ACTIVE && AJ_GetTimeDifference(&now, &start) < timeout);

    if (AJ_SerialLinkParams.linkState != AJ_LINK_ACTIVE) {
        AJ_InfoPrintf(("Failed to establish active SLAP connection in %u msec\n", timeout));
        AJ_SerialShutdown();
        return AJ_ERR_TIMEOUT;
    }
#endif

    status = AJ_Authenticate(bus);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Authenticate status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }

    // subscribe to the signal NameOwnerChanged and wait for the response
    status = AJ_BusSetSignalRule(bus, "type='signal',member='NameOwnerChanged',interface='org.freedesktop.DBus'", AJ_BUS_SIGNAL_ALLOW);

ExitConnect:

    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): status=%s\n", AJ_StatusText(status)));
        AJ_Disconnect(bus);
    }
    return status;
}

AJ_Status AJ_FindBusAndConnect(AJ_BusAttachment* bus, const char* serviceName, uint32_t timeout)
{
    AJ_Status status;
    AJ_Service service;

#ifdef AJ_SERIAL_CONNECTION
    AJ_Time start, now;
    AJ_InitTimer(&start);
#endif

    AJ_InfoPrintf(("AJ_Connect(bus=0x%p, serviceName=\"%s\", timeout=%d.)\n", bus, serviceName, timeout));

    /*
     * Clear the bus struct
     */
    memset(bus, 0, sizeof(AJ_BusAttachment));
    /*
     * Clear stale name->GUID mappings
     */
    AJ_GUID_ClearNameMap();

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
        AJ_InfoPrintf(("AJ_Connect(): AJ_Discover status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }
#elif defined AJ_SERIAL_CONNECTION
    // don't bother with discovery, we are connected to a daemon.
    // however, take this opportunity to bring up the serial connection
    status = AJ_Serial_Up();
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Serial_Up status=%s\n", AJ_StatusText(status)));
    }
#else
    status = AJ_Discover(serviceName, &service, timeout);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Discover status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }
#endif
    status = AJ_Net_Connect(&bus->sock, service.ipv4port, service.addrTypes & AJ_ADDR_IPV4, &service.ipv4);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Net_Connect status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }

#ifdef AJ_SERIAL_CONNECTION
    // run the state machine for long enough to (hopefully) do the SLAP handshake
    do {
        AJ_StateMachine();
        AJ_InitTimer(&now);
    } while (AJ_SerialLinkParams.linkState != AJ_LINK_ACTIVE && AJ_GetTimeDifference(&now, &start) < timeout);

    if (AJ_SerialLinkParams.linkState != AJ_LINK_ACTIVE) {
        AJ_InfoPrintf(("Failed to establish active SLAP connection in %u msec\n", timeout));
        AJ_SerialShutdown();
        return AJ_ERR_TIMEOUT;
    }
#endif

    status = AJ_Authenticate(bus);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): AJ_Authenticate status=%s\n", AJ_StatusText(status)));
        goto ExitConnect;
    }

    // subscribe to the signal NameOwnerChanged and wait for the response
    status = AJ_BusSetSignalRule(bus, "type='signal',member='NameOwnerChanged',interface='org.freedesktop.DBus'", AJ_BUS_SIGNAL_ALLOW);

ExitConnect:

    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Connect(): status=%s\n", AJ_StatusText(status)));
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

#ifdef AJ_SERIAL_CONNECTION
    AJ_SerialShutdown();
#endif
}
