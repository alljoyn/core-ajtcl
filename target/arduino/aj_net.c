/**
 * @file
 */
/******************************************************************************
 *  *    Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
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
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include "aj_target.h"
#include "aj_bufio.h"
#include "aj_net.h"
#include "aj_util.h"
#include "aj_debug.h"

#ifdef WIFI_UDP_WORKING
#include <SPI.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiUdp.h>
#else
#include <SPI.h>
#include <Ethernet.h>
#include <EthernetUdp.h>
#endif


static uint8_t rxDataStash[256];
static uint16_t rxLeftover = 0;

/*
 * IANA assigned IPv4 multicast group for AllJoyn.
 */
static const char AJ_IPV4_MULTICAST_GROUP[] = "224.0.0.113";

/*
 * IANA assigned IPv6 multicast group for AllJoyn.
 */
static const char AJ_IPV6_MULTICAST_GROUP[] = "ff02::13a";

/*
 * IANA assigned UDP multicast port for AllJoyn
 */
#define AJ_UDP_PORT 9956

#ifdef WIFI_UDP_WORKING
static WiFiClient g_client;
static WiFiUDP g_clientUDP;
#else
static EthernetClient g_client;
static EthernetUDP g_clientUDP;
#endif

AJ_Status AJ_Net_Send(AJ_IOBuffer* buf)
{
    uint32_t ret;
    uint32_t tx = AJ_IO_BUF_AVAIL(buf);

    if (tx > 0) {
        ret = g_client.write(buf->readPtr, tx);
        if (ret == 0) {
            #ifndef NDEBUG
            AJ_Printf("error sending %d\n", g_client.getWriteError());
            #endif
            return AJ_ERR_WRITE;
        }
        buf->readPtr += ret;
    }
    if (AJ_IO_BUF_AVAIL(buf) == 0) {
        AJ_IO_BUF_RESET(buf);
    }
    return AJ_OK;
}

AJ_Status AJ_Net_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    AJ_Status status = AJ_ERR_READ;
    uint32_t ret;
    uint32_t rx = AJ_IO_BUF_SPACE(buf);
    uint32_t recvd = 0;
    unsigned long Recv_lastCall = millis();

#ifndef NDEBUG
    AJ_Printf("len: %d rx: %d timeout %d\n", len, rx, timeout);
#endif


    // first we need to clear out our buffer
    uint32_t M = 0;
    if (rxLeftover != 0) {
        // there was something leftover from before,
        AJ_Printf("leftover was: %d\n", rxLeftover);
        M = min(rx, rxLeftover);
        memcpy(buf->writePtr, rxDataStash, M);  // copy leftover into buffer.
        buf->writePtr += M;  // move the data pointer over
        memmove(rxDataStash, rxDataStash + M, rxLeftover - M); // shift left-overs toward the start.
        rxLeftover -= M;
        recvd += M;

        // we have read as many bytes as we can
        // higher level isn't requesting any more
        if (recvd == rx) {
            return AJ_OK;
        }
    }


    if ((M != 0) && (rxLeftover != 0)) {
        AJ_Printf("M was: %d, rxLeftover was: %d\n", M, rxLeftover);
    }

    // wait for data to become available
    // time out if nothing arrives
    while (g_client.connected() &&
           g_client.available() == 0 &&
           (millis() - Recv_lastCall < timeout)) {
        delay(50); // wait for data or timeout
    }

    // return timeout if nothing is available
    AJ_Printf("millis %d, Last_call %d timeout %d Avail: %d\n", millis(), Recv_lastCall, timeout, g_client.available());
    if (g_client.connected() && (millis() - Recv_lastCall >= timeout) && (g_client.available() == 0)) {
        return AJ_ERR_TIMEOUT;
    }

    if (g_client.connected()) {
        uint32_t askFor = rx;
        askFor -= M;
        AJ_Printf("ask for: %d\n", askFor);
        ret = g_client.read(buf->writePtr, askFor);
        AJ_Printf("Recv: ret %d  askfor %d\n", ret, askFor);

        if (askFor < ret) {
            AJ_Printf("BUFFER OVERRUN: askFor=%u, ret=%u\n", askFor, ret);
        }

        if (ret == -1) {
#ifndef NDEBUG
            AJ_Printf("Recv failed\n");
#endif
            status = AJ_ERR_READ;
        } else {
            AJ_Printf("ret now %d\n", ret);
            AJ_DumpBytes("Recv", buf->writePtr, ret);

            if (ret > askFor) {
                AJ_Printf("new leftover %d\n", ret - askFor);
                // now shove the extra into the stash
                memcpy(rxDataStash + rxLeftover, buf->writePtr + askFor, ret - askFor);
                rxLeftover += (ret - askFor);
                buf->writePtr += rx;
            } else {
                buf->writePtr += ret;
            }
            status = AJ_OK;
        }
    }

    return status;
}

/*
 * Need enough RX buffer space to receive a complete name service packet when
 * used in UDP mode.  NS expects MTU of 1500 subtracts UDP, IP and Ethernet
 * Type II overhead.  1500 - 8 -20 - 18 = 1454.  txData buffer size needs to
 * be big enough to hold a NS WHO-HAS for one name (4 + 2 + 256 = 262) in UDP
 * mode.  TCP buffer size dominates in that case.
 */
static uint8_t rxData[1454];
static uint8_t txData[1024];

AJ_Status AJ_Net_Connect(AJ_NetSocket* netSock, uint16_t port, uint8_t addrType, const uint32_t* addr)
{
    int ret;

    IPAddress ip(*addr);
    ret = g_client.connect(ip, port);

    Serial.print("Connecting to: ");
    Serial.print(ip);
    Serial.print(':');
    Serial.println(port);

    if (ret == -1) {
        AJ_Printf("connect() failed: %d\n", ret);
        return AJ_ERR_CONNECT;
    } else {
        AJ_IOBufInit(&netSock->rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, (void*)&g_client);
        netSock->rx.recv = AJ_Net_Recv;
        AJ_IOBufInit(&netSock->tx, txData, sizeof(txData), AJ_IO_BUF_TX, (void*)&g_client);
        netSock->tx.send = AJ_Net_Send;
        return AJ_OK;
    }
    return AJ_ERR_CONNECT;
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
    g_client.stop();
}

AJ_Status AJ_Net_SendTo(AJ_IOBuffer* buf)
{
    int ret;
    uint32_t tx = AJ_IO_BUF_AVAIL(buf);

    if (tx > 0) {
        // send to subnet-directed broadcast address
        IPAddress subnet = Ethernet.subnetMask();
        IPAddress localIp = Ethernet.localIP();
        uint32_t directedBcastAddr = (uint32_t(subnet) & uint32_t(localIp)) | (~uint32_t(subnet));
        IPAddress a(directedBcastAddr);
        ret = g_clientUDP.beginPacket(IPAddress(directedBcastAddr), AJ_UDP_PORT);
        AJ_Printf("SendTo beginPacket to %d.%d.%d.%d, result = %d\n", a[0], a[1], a[2], a[3],  ret);
        if (ret == 0) {
            AJ_Printf("no sender\n");
        }

        ret = g_clientUDP.write(buf->readPtr, tx);
        AJ_Printf("SendTo write %d\n", ret);
        if (ret == 0) {
            AJ_Printf("no bytes\n");
            return AJ_ERR_WRITE;
        }

        buf->readPtr += ret;

        ret = g_clientUDP.endPacket();
        if (ret == 0) {
            AJ_Printf("err endpacket\n");
            return AJ_ERR_WRITE;
        }

    }
    AJ_IO_BUF_RESET(buf);
    return AJ_OK;
}

AJ_Status AJ_Net_RecvFrom(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    AJ_Printf("RecvFrom ");
    AJ_Status status = AJ_OK;
    int ret;
    uint32_t rx = AJ_IO_BUF_SPACE(buf);
    unsigned long Recv_lastCall = millis();

#ifndef NDEBUG
    AJ_Printf("len: %d rx: %d timeout %d\n", len, rx, timeout);
#endif

    rx = min(rx, len);

    while ((g_clientUDP.parsePacket() == 0) && (millis() - Recv_lastCall < timeout)) {
        delay(10); // wait for data or timeout
    }

    AJ_Printf("millis %d, Last_call %d timeout %d Avail: %d\n", millis(), Recv_lastCall, timeout, g_clientUDP.available());
    ret = g_clientUDP.read(buf->writePtr, rx);
    AJ_Printf("RecvFrom: ret %d  rx %d\n", ret, rx);

    if (ret == -1) {
        status = AJ_ERR_READ;
    } else {
        if (ret != -1) {
            AJ_DumpBytes("RecvFrom", buf->writePtr, ret);
        }
        buf->writePtr += ret;
        status = AJ_OK;
    }
    return status;
}

uint16_t AJ_EphemeralPort(void)
{
    // Return a random port number in the IANA-suggested range
    return 49152 + random(65535 - 49152);
}

AJ_Status AJ_Net_MCastUp(AJ_NetSocket* netSock)
{
    uint8_t ret = 0;
    //
    // Arduino does not choose an ephemeral port if we enter 0 -- it happily
    // uses 0 and then increments each time we bind, up through the well-known
    // system ports.
    //
    ret = g_clientUDP.begin(AJ_EphemeralPort());

    if (ret != 1) {
        g_clientUDP.stop();
        return AJ_ERR_READ;
    } else {
        AJ_IOBufInit(&netSock->rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, (void*)&g_clientUDP);
        netSock->rx.recv = AJ_Net_RecvFrom;
        AJ_IOBufInit(&netSock->tx, txData, sizeof(txData), AJ_IO_BUF_TX, (void*)&g_clientUDP);
        netSock->tx.send = AJ_Net_SendTo;
    }

    return AJ_OK;
}

void AJ_Net_MCastDown(AJ_NetSocket* netSock)
{
    g_clientUDP.flush();
    g_clientUDP.stop();
}


AJ_Status AJ_Net_Up()
{
    return AJ_OK;
}

void AJ_Net_Down()
{
}