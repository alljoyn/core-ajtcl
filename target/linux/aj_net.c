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
#define AJ_MODULE NET

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>

#include "aj_target.h"
#include "aj_bufio.h"
#include "aj_net.h"
#include "aj_util.h"
#include "aj_debug.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgNET = 0;
#endif

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

/**
 * Target-specific context for network I/O
 */
typedef struct {
    int tcpSock;
    int udpSock;
    int udp6Sock;
} NetContext;

static NetContext netContext = { INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET };

static AJ_Status CloseNetSock(AJ_NetSocket* netSock)
{
    NetContext* context = (NetContext*)netSock->rx.context;
    if (context) {
        if (context->tcpSock != INVALID_SOCKET) {
            struct linger l;
            l.l_onoff = 1;
            l.l_linger = 0;
            setsockopt(context->tcpSock, SOL_SOCKET, SO_LINGER, (void*)&l, sizeof(l));
            shutdown(context->tcpSock, SHUT_RDWR);
            close(context->tcpSock);
        }
        if (context->udpSock != INVALID_SOCKET) {
            close(context->udpSock);
        }
        if (context->udp6Sock != INVALID_SOCKET) {
            close(context->udp6Sock);
        }

        context->tcpSock = context->udpSock = context->udp6Sock = INVALID_SOCKET;
        memset(netSock, 0, sizeof(AJ_NetSocket));
    }
    return AJ_OK;
}

AJ_Status AJ_Net_Send(AJ_IOBuffer* buf)
{
    NetContext* context = (NetContext*) buf->context;
    ssize_t ret;
    size_t tx = AJ_IO_BUF_AVAIL(buf);

    AJ_InfoPrintf(("AJ_Net_Send(buf=0x%p)\n", buf));

    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        ret = send(context->tcpSock, buf->readPtr, tx, MSG_NOSIGNAL);
        if (ret == -1) {
            AJ_ErrPrintf(("AJ_Net_Send(): send() failed. errno=\"%s\", status=AJ_ERR_WRITE\n", strerror(errno)));
            return AJ_ERR_WRITE;
        }
        buf->readPtr += ret;
    }
    if (AJ_IO_BUF_AVAIL(buf) == 0) {
        AJ_IO_BUF_RESET(buf);
    }

    AJ_InfoPrintf(("AJ_Net_Send(): status=AJ_OK\n"));
    return AJ_OK;
}

/*
 * An eventfd handle used for interrupting a network read blocked on select
 */
static int interruptFd = INVALID_SOCKET;

/*
 * The socket that is blocked in select
 */
static uint8_t blocked;

/*
 * This function is called to cancel a pending select.
 */
void AJ_Net_Interrupt()
{
    if (blocked) {
        uint64_t u64;
        write(interruptFd, &u64, sizeof(u64));
    }
}

AJ_Status AJ_Net_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    NetContext* context = (NetContext*) buf->context;
    AJ_Status status = AJ_OK;
    size_t rx = AJ_IO_BUF_SPACE(buf);
    fd_set fds;
    int rc = 0;
    int maxFd = context->tcpSock;
    struct timeval tv = { timeout / 1000, 1000 * (timeout % 1000) };

    AJ_InfoPrintf(("AJ_Net_Recv(buf=0x%p, len=%d., timeout=%d.)\n", buf, len, timeout));

    assert(buf->direction == AJ_IO_BUF_RX);

    FD_ZERO(&fds);
    FD_SET(context->tcpSock, &fds);
    if (interruptFd >= 0) {
        FD_SET(interruptFd, &fds);
        maxFd = max(maxFd, interruptFd);
    }
    blocked = TRUE;
    rc = select(maxFd + 1, &fds, NULL, NULL, &tv);
    blocked = FALSE;
    if (rc == 0) {
        return AJ_ERR_TIMEOUT;
    }
    if ((interruptFd >= 0) && FD_ISSET(interruptFd, &fds)) {
        uint64_t u64;
        read(interruptFd, &u64, sizeof(u64));
        return AJ_ERR_INTERRUPTED;
    }
    rx = min(rx, len);
    if (rx) {
        ssize_t ret = recv(context->tcpSock, buf->writePtr, rx, 0);
        if ((ret == -1) || (ret == 0)) {
            AJ_ErrPrintf(("AJ_Net_Recv(): recv() failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
            status = AJ_ERR_READ;
        } else {
            buf->writePtr += ret;
        }
    }
    AJ_InfoPrintf(("AJ_Net_Recv(): status=%s\n", AJ_StatusText(status)));
    return status;
}

static uint8_t rxData[1024];
static uint8_t txData[1500];

AJ_Status AJ_Net_Connect(AJ_NetSocket* netSock, uint16_t port, uint8_t addrType, const uint32_t* addr)
{
    int ret;
    struct sockaddr_storage addrBuf;
    socklen_t addrSize;
    int tcpSock = INVALID_SOCKET;

    AJ_InfoPrintf(("AJ_Net_Connect(netSock=0x%p, port=%d., addrType=%d., addr=0x%p)\n", netSock, port, addrType, addr));

    interruptFd = eventfd(0, EFD_NONBLOCK);
    if (interruptFd < 0) {
        AJ_ErrPrintf(("AJ_Net_Connect(): failed to created interrupt event\n"));
        goto ConnectError;
    }

    memset(&addrBuf, 0, sizeof(addrBuf));

    tcpSock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock == INVALID_SOCKET) {
        AJ_ErrPrintf(("AJ_Net_Connect(): socket() failed.  status=AJ_ERR_CONNECT\n"));
        goto ConnectError;
    }
    if (addrType == AJ_ADDR_IPV4) {
        struct sockaddr_in* sa = (struct sockaddr_in*)&addrBuf;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr.s_addr = *addr;
        addrSize = sizeof(struct sockaddr_in);
        AJ_InfoPrintf(("AJ_Net_Connect(): Connect to \"%s:%u\"\n", inet_ntoa(sa->sin_addr), port));;
    } else {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)&addrBuf;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        memcpy(sa->sin6_addr.s6_addr, addr, sizeof(sa->sin6_addr.s6_addr));
        addrSize = sizeof(struct sockaddr_in6);
    }
    ret = connect(tcpSock, (struct sockaddr*)&addrBuf, addrSize);
    if (ret < 0) {
        AJ_ErrPrintf(("AJ_Net_Connect(): connect() failed. errno=\"%s\", status=AJ_ERR_CONNECT\n", strerror(errno)));
        goto ConnectError;
    } else {
        netContext.tcpSock = tcpSock;
        AJ_IOBufInit(&netSock->rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, &netContext);
        netSock->rx.recv = AJ_Net_Recv;
        AJ_IOBufInit(&netSock->tx, txData, sizeof(txData), AJ_IO_BUF_TX, &netContext);
        netSock->tx.send = AJ_Net_Send;
        AJ_InfoPrintf(("AJ_Net_Connect(): status=AJ_OK\n"));
    }

    return AJ_OK;

ConnectError:
    if (interruptFd != INVALID_SOCKET) {
        close(interruptFd);
        interruptFd = INVALID_SOCKET;
    }

    if (tcpSock != INVALID_SOCKET) {
        close(tcpSock);
    }

    return AJ_ERR_CONNECT;
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
    if (interruptFd >= 0) {
        close(interruptFd);
        interruptFd = -1;
    }
    CloseNetSock(netSock);
}

static void sendToBroadcast(int sock, void* ptr, size_t tx)
{
    struct ifaddrs* addrs;
    struct ifaddrs* addr;

    getifaddrs(&addrs);
    addr = addrs;

    while (addr != NULL) {
        // only care about IPV4
        if (addr->ifa_addr != NULL && addr->ifa_addr->sa_family == AF_INET) {
            char buf[INET_ADDRSTRLEN];
            struct sockaddr_in* sin_bcast = (struct sockaddr_in*) addr->ifa_ifu.ifu_broadaddr;
            sin_bcast->sin_port = htons(AJ_UDP_PORT);
            inet_ntop(AF_INET, &(sin_bcast->sin_addr), buf, sizeof(buf));
            AJ_InfoPrintf(("sendToBroadcast: sending to bcast addr %s\n", buf));
            sendto(sock, ptr, tx, MSG_NOSIGNAL, (struct sockaddr*) sin_bcast, sizeof(struct sockaddr_in));
        }

        addr = addr->ifa_next;
    }
    freeifaddrs(addrs);
}

AJ_Status AJ_Net_SendTo(AJ_IOBuffer* buf)
{
    ssize_t ret = -1;
    uint8_t sendSucceeded = FALSE;
    size_t tx = AJ_IO_BUF_AVAIL(buf);
    NetContext* context = (NetContext*) buf->context;
    AJ_InfoPrintf(("AJ_Net_SendTo(buf=0x%p)\n", buf));
    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        if (context->udpSock != INVALID_SOCKET) {
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_port = htons(AJ_UDP_PORT);

            if (inet_pton(AF_INET, AJ_IPV4_MULTICAST_GROUP, &sin.sin_addr) == 1) {
                ret = sendto(context->udpSock, buf->readPtr, tx, MSG_NOSIGNAL, (struct sockaddr*)&sin, sizeof(sin));
                if (tx == ret) {
                    sendSucceeded = TRUE;
                }
            } else {
                AJ_ErrPrintf(("AJ_Net_SendTo(): Invalid address IP address. errno=\"%s\"", strerror(errno)));
            }

            sendToBroadcast(context->udpSock, buf->readPtr, tx);
        }

        // now sendto the ipv6 address
        if (context->udp6Sock != INVALID_SOCKET) {
            struct sockaddr_in6 sin6;
            sin6.sin6_family = AF_INET6;
            sin6.sin6_flowinfo = 0;
            sin6.sin6_scope_id = 0;
            sin6.sin6_port = htons(AJ_UDP_PORT);
            if (inet_pton(AF_INET6, AJ_IPV6_MULTICAST_GROUP, &sin6.sin6_addr) == 1) {
                ret = sendto(context->udp6Sock, buf->readPtr, tx, MSG_NOSIGNAL, (struct sockaddr*) &sin6, sizeof(sin6));
                if (tx == ret) {
                    sendSucceeded = TRUE;
                }
            } else {
                AJ_ErrPrintf(("AJ_Net_SendTo(): Invalid address IP address. errno=\"%s\"", strerror(errno)));
            }
        }

        if (!sendSucceeded) {
            /* Both IPv4 and IPv6 failed, return an error */
            AJ_ErrPrintf(("AJ_Net_SendTo(): sendto() failed. errno=\"%s\", status=AJ_ERR_WRITE\n", strerror(errno)));
            return AJ_ERR_WRITE;
        }
        buf->readPtr += ret;
    }
    AJ_IO_BUF_RESET(buf);
    AJ_InfoPrintf(("AJ_Net_SendTo(): status=AJ_OK\n"));
    return AJ_OK;
}

AJ_Status AJ_Net_RecvFrom(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    NetContext* context = (NetContext*) buf->context;
    AJ_Status status = AJ_OK;
    ssize_t ret;
    size_t rx;
    fd_set fds;
    int maxFd = INVALID_SOCKET;
    int rc = 0;
    struct timeval tv = { timeout / 1000, 1000 * (timeout % 1000) };

    AJ_InfoPrintf(("AJ_Net_RecvFrom(buf=0x%p, len=%d., timeout=%d.)\n", buf, len, timeout));

    assert(buf->direction == AJ_IO_BUF_RX);

    FD_ZERO(&fds);
    if (context->udpSock != INVALID_SOCKET) {
        FD_SET(context->udpSock, &fds);
    }

    if (context->udp6Sock != INVALID_SOCKET) {
        FD_SET(context->udp6Sock, &fds);
    }

    maxFd = max(context->udp6Sock, context->udpSock);

    rc = select(maxFd + 1, &fds, NULL, NULL, &tv);
    if (rc == 0) {
        AJ_InfoPrintf(("AJ_Net_RecvFrom(): select() timed out. status=AJ_ERR_TIMEOUT\n"));
        return AJ_ERR_TIMEOUT;
    }


    // we need to read from whichever socket has data availble.
    // if both sockets are ready, read from both in order to
    // reset the state

    rx = AJ_IO_BUF_SPACE(buf);
    if (context->udp6Sock != INVALID_SOCKET && FD_ISSET(context->udp6Sock, &fds)) {
        rx = min(rx, len);
        if (rx) {
            ret = recvfrom(context->udp6Sock, buf->writePtr, rx, 0, NULL, 0);
            if (ret == -1) {
                AJ_ErrPrintf(("AJ_Net_RecvFrom(): recvfrom() failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
                status = AJ_ERR_READ;
            } else {
                buf->writePtr += ret;
                status = AJ_OK;
            }
        }
    }

    rx = AJ_IO_BUF_SPACE(buf);
    if (context->udpSock != INVALID_SOCKET && FD_ISSET(context->udpSock, &fds)) {
        rx = min(rx, len);
        if (rx) {
            ret = recvfrom(context->udpSock, buf->writePtr, rx, 0, NULL, 0);
            if (ret == -1) {
                AJ_ErrPrintf(("AJ_Net_RecvFrom(): recvfrom() failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
                status = AJ_ERR_READ;
            } else {
                buf->writePtr += ret;
                status = AJ_OK;
            }
        }
    }

    AJ_InfoPrintf(("AJ_Net_RecvFrom(): status=%s\n", AJ_StatusText(status)));
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

static int MCastUp4()
{
    int ret;
    struct ip_mreq mreq;
    struct sockaddr_in sin;
    int reuse = 1;
    int bcast = 1;
    int mcastSock;

    AJ_InfoPrintf(("MCastUp4()\n"));

    mcastSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mcastSock == INVALID_SOCKET) {
        AJ_ErrPrintf(("MCastUp4(): socket() fails. status=AJ_ERR_READ\n"));
        return INVALID_SOCKET;
    }

    ret = setsockopt(mcastSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (ret != 0) {
        AJ_ErrPrintf(("MCastUp4(): setsockopt(SO_REUSEADDR) failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        goto ExitError;
    }

    // enable IP broadcast on this socket.
    // This is needed for bcast router discovery
    int r = setsockopt(mcastSock, SOL_SOCKET, SO_BROADCAST, (void*) &bcast, sizeof(bcast));
    if (r != 0) {
        AJ_ErrPrintf(("BcastUp4(): setsockopt(SOL_SOCKET, SO_BROADCAST) failed. errno=\"%s\"\n", strerror(errno)));
        goto ExitError;
    }

    /*
     * Bind an ephemeral port
     */
    sin.sin_family = AF_INET;
    sin.sin_port = htons(0);
    sin.sin_addr.s_addr = INADDR_ANY;
    ret = bind(mcastSock, (struct sockaddr*) &sin, sizeof(sin));
    if (ret < 0) {
        AJ_ErrPrintf(("MCastUp4(): bind() failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        goto ExitError;
    }

    /*
     * Join our multicast group
     */
    inet_pton(AF_INET, AJ_IPV4_MULTICAST_GROUP, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = INADDR_ANY;
    ret = setsockopt(mcastSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (ret < 0) {
        AJ_ErrPrintf(("MCastUp4(): setsockopt(IP_ADD_MEMBERSHIP) failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        goto ExitError;
    }

    return mcastSock;

ExitError:
    close(mcastSock);
    return INVALID_SOCKET;
}

static int MCastUp6()
{
    int ret;
    struct ipv6_mreq mreq6;
    struct sockaddr_in6 sin6;
    int reuse = 1;
    int mcastSock;

    AJ_InfoPrintf(("MCastUp6()\n"));

    mcastSock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (mcastSock == INVALID_SOCKET) {
        AJ_ErrPrintf(("MCastUp6(): socket() fails. errno=\"%s\" status=AJ_ERR_READ\n", strerror(errno)));
        return INVALID_SOCKET;
    }

    ret = setsockopt(mcastSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (ret != 0) {
        AJ_ErrPrintf(("MCastUp6(): setsockopt(SO_REUSEADDR) failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        goto ExitError;
    }

    /*
     * Bind an ephemeral port
     */
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(0);
    sin6.sin6_addr = in6addr_any;
    ret = bind(mcastSock, (struct sockaddr*) &sin6, sizeof(sin6));
    if (ret < 0) {
        AJ_ErrPrintf(("MCastUp6(): bind() failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        goto ExitError;
    }

    /*
     * Join our multicast group
     */
    inet_pton(AF_INET6, AJ_IPV6_MULTICAST_GROUP, &mreq6.ipv6mr_multiaddr);
    mreq6.ipv6mr_interface = 0;
    ret = setsockopt(mcastSock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
    if (ret < 0) {
        AJ_ErrPrintf(("MCastUp6(): setsockopt(IP_ADD_MEMBERSHIP) failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        goto ExitError;
    }

    return mcastSock;

ExitError:
    close(mcastSock);
    return INVALID_SOCKET;
}



AJ_Status AJ_Net_MCastUp(AJ_NetSocket* netSock)
{
    AJ_Status status = AJ_ERR_READ;
    netContext.udpSock = MCastUp4();
    netContext.udp6Sock = MCastUp6();

    if (netContext.udpSock != INVALID_SOCKET || netContext.udp6Sock != INVALID_SOCKET) {
        AJ_IOBufInit(&netSock->rx, rxDataMCast, sizeof(rxDataMCast), AJ_IO_BUF_RX, &netContext);
        netSock->rx.recv = AJ_Net_RecvFrom;
        AJ_IOBufInit(&netSock->tx, txDataMCast, sizeof(txDataMCast), AJ_IO_BUF_TX, &netContext);
        netSock->tx.send = AJ_Net_SendTo;
        status = AJ_OK;
    }

    return status;
}

void AJ_Net_MCastDown(AJ_NetSocket* netSock)
{
    NetContext* context = (NetContext*) netSock->rx.context;
    AJ_InfoPrintf(("AJ_Net_MCastDown(nexSock=0x%p)\n", netSock));

    if (context->udpSock != INVALID_SOCKET) {
        /*
         * Leave our multicast group
         */
        struct ip_mreq mreq;
        inet_pton(AF_INET, AJ_IPV4_MULTICAST_GROUP, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        setsockopt(context->udpSock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*) &mreq, sizeof(mreq));
    }

    if (context->udp6Sock != INVALID_SOCKET) {
        struct ipv6_mreq mreq6;
        inet_pton(AF_INET6, AJ_IPV6_MULTICAST_GROUP, &mreq6.ipv6mr_multiaddr);
        mreq6.ipv6mr_interface = 0;
        setsockopt(context->udp6Sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq6, sizeof(mreq6));
    }

    CloseNetSock(netSock);
}
