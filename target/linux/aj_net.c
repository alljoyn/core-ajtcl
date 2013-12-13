/**
 * @file
 */
/******************************************************************************
 * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "aj_target.h"
#include "aj_bufio.h"
#include "aj_net.h"
#include "aj_util.h"

#define INVALID_SOCKET (-1)

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

AJ_Status AJ_Net_Send(AJ_IOBuffer* buf)
{
    ssize_t ret;
    size_t tx = AJ_IO_BUF_AVAIL(buf);

    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        ret = send((int)buf->context, buf->readPtr, tx, 0);
        if (ret == -1) {
#ifndef NDEBUG
            fprintf(stderr, "send() failed: %s\n", strerror(errno));
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
    AJ_Status status = AJ_OK;
    size_t rx = AJ_IO_BUF_SPACE(buf);
    fd_set fds;
    int maxFd = INVALID_SOCKET;
    int rc = 0;
    struct timeval tv = { timeout / 1000, 1000 * (timeout % 1000) };

    assert(buf->direction == AJ_IO_BUF_RX);

    FD_ZERO(&fds);
    FD_SET((int)buf->context, &fds);
    maxFd = max(maxFd, (int)buf->context);
    rc = select(maxFd + 1, &fds, NULL, NULL, &tv);
    if (rc == 0) {
        return AJ_ERR_TIMEOUT;
    }

    rx = min(rx, len);
    if (rx) {
        ssize_t ret = recv((int)buf->context, buf->writePtr, rx, 0);
        if ((ret == -1) || (ret == 0)) {
#ifndef NDEBUG
            fprintf(stderr, "recv() failed: %s\n", strerror(errno));
#endif
            status = AJ_ERR_READ;
        } else {
            buf->writePtr += ret;
        }
    }
    return status;
}


static uint8_t rxData[1024];
static uint8_t txData[1024];

AJ_Status AJ_Net_Connect(AJ_NetSocket* netSock, uint16_t port, uint8_t addrType, const uint32_t* addr)
{
    int ret;
    struct sockaddr_storage addrBuf;
    socklen_t addrSize;

    memset(&addrBuf, 0, sizeof(addrBuf));

    int tcpSock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock == INVALID_SOCKET) {
        return AJ_ERR_CONNECT;
    }
    if (addrType == AJ_ADDR_IPV4) {
        struct sockaddr_in* sa = (struct sockaddr_in*)&addrBuf;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr.s_addr = *addr;
        addrSize = sizeof(*sa);
        printf("CONNECT: %s:%u\n", inet_ntoa(sa->sin_addr), port);
    } else {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)&addrBuf;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        memcpy(sa->sin6_addr.s6_addr, addr, sizeof(sa->sin6_addr.s6_addr));
        addrSize = sizeof(*sa);
    }
    ret = connect(tcpSock, (struct sockaddr*)&addrBuf, addrSize);
    if (ret < 0) {
#ifndef NDEBUG
        fprintf(stderr, "connect() failed: %d\n", ret);
#endif
        return AJ_ERR_CONNECT;
    } else {
        AJ_IOBufInit(&netSock->rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, (void*)tcpSock);
        netSock->rx.recv = AJ_Net_Recv;
        AJ_IOBufInit(&netSock->tx, txData, sizeof(txData), AJ_IO_BUF_TX, (void*)tcpSock);
        netSock->tx.send = AJ_Net_Send;
        return AJ_OK;
    }
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
    int tcpSock = (int)netSock->rx.context;
    if (tcpSock != INVALID_SOCKET) {
        shutdown(tcpSock, SHUT_RDWR);
        close(tcpSock);
        tcpSock = INVALID_SOCKET;
    }
}

AJ_Status AJ_Net_SendTo(AJ_IOBuffer* buf)
{
    ssize_t ret;
    size_t tx = AJ_IO_BUF_AVAIL(buf);

    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        /*
         * Only multicasting over IPv4 for now
         */
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(AJ_UDP_PORT);
        sin.sin_addr.s_addr = inet_addr(AJ_IPV4_MULTICAST_GROUP);
        ret = sendto((int)buf->context, buf->readPtr, tx, 0, (struct sockaddr*)&sin, sizeof(sin));
        if (ret == -1) {
#ifndef NDEBUG
            fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
#endif
            return AJ_ERR_WRITE;
        }
        buf->readPtr += ret;
    }
    AJ_IO_BUF_RESET(buf);
    return AJ_OK;
}

AJ_Status AJ_Net_RecvFrom(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    AJ_Status status;
    ssize_t ret;
    size_t rx = AJ_IO_BUF_SPACE(buf);
    fd_set fds;
    int maxFd = INVALID_SOCKET;
    int rc = 0;
    struct timeval tv = { timeout / 1000, 1000 * (timeout % 1000) };

    assert(buf->direction == AJ_IO_BUF_RX);

    FD_ZERO(&fds);
    FD_SET((int) buf->context, &fds);
    maxFd = max(maxFd, (int)buf->context);
    rc = select(maxFd + 1, &fds, NULL, NULL, &tv);
    if (rc == 0) {
        return AJ_ERR_TIMEOUT;
    }

    rx = min(rx, len);
    ret = recvfrom((int)buf->context, buf->writePtr, rx, 0, NULL, 0);
    if (ret == -1) {
        status = AJ_ERR_READ;
    } else {
        buf->writePtr += ret;
        status = AJ_OK;
    }
    return status;
}

/*
 * Need enough space to receive a complete name service packet when used in UDP
 * mode.  NS expects MTU of 1500 subtracts UDP, IP and ethertype overhead.
 * 1500 - 8 -20 - 18 = 1454.  txData buffer size needs to be big enough to hold
 * a NS WHO-HAS for one name (4 + 2 + 256 = 262)
 */
static uint8_t rxDataMCast[1454];
static uint8_t txDataMCast[262];

#ifndef SO_REUSEPORT
#define SO_REUSEPORT SO_REUSEADDR
#endif

AJ_Status AJ_Net_MCastUp(AJ_NetSocket* netSock)
{
    int ret;
    struct ip_mreq mreq;
    struct sockaddr_in sin;
    int reuse = 1;

    int mcastSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mcastSock == INVALID_SOCKET) {
        return AJ_ERR_READ;
    }

    ret = setsockopt(mcastSock, SOL_SOCKET, SO_REUSEPORT, (void*) &reuse, sizeof(reuse));
    if (ret != 0) {
        fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
        close(mcastSock);
        return AJ_ERR_READ;
    }

    /*
     * Bind an ephemeral port
     */
    sin.sin_family = AF_INET;
    sin.sin_port = htons(0);
    sin.sin_addr.s_addr = INADDR_ANY;
    ret = bind(mcastSock, (struct sockaddr*)&sin, sizeof(sin));
    if (ret < 0) {
        return AJ_ERR_READ;
    }

    /*
     * Join our multicast group
     */
    mreq.imr_multiaddr.s_addr = inet_addr(AJ_IPV4_MULTICAST_GROUP);
    mreq.imr_interface.s_addr = INADDR_ANY;
    ret = setsockopt(mcastSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));
    if (ret < 0) {
        close(mcastSock);
        return AJ_ERR_READ;
    } else {
        AJ_IOBufInit(&netSock->rx, rxDataMCast, sizeof(rxDataMCast), AJ_IO_BUF_RX, (void*)mcastSock);
        netSock->rx.recv = AJ_Net_RecvFrom;
        AJ_IOBufInit(&netSock->tx, txDataMCast, sizeof(txDataMCast), AJ_IO_BUF_TX, (void*)mcastSock);
        netSock->tx.send = AJ_Net_SendTo;
    }

    return AJ_OK;
}

void AJ_Net_MCastDown(AJ_NetSocket* netSock)
{
    struct ip_mreq mreq;
    int mcastSock = (int)netSock->rx.context;

    if (mcastSock != INVALID_SOCKET) {
        /*
         * Leave our multicast group
         */
        mreq.imr_multiaddr.s_addr = inet_addr(AJ_IPV4_MULTICAST_GROUP);
        mreq.imr_interface.s_addr = INADDR_ANY;
        setsockopt(mcastSock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*) &mreq, sizeof(mreq));
        shutdown(mcastSock, SHUT_RDWR);
        close(mcastSock);
        mcastSock = INVALID_SOCKET;
    }
}


AJ_Status AJ_Net_Up()
{
    return AJ_OK;
}

void AJ_Net_Down()
{
}