/**
 * @file Alljoyn network function implementations
 */
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "aj_target.h"
#include "aj_bufio.h"
#include "aj_net.h"
#include "aj_util.h"
#include "aj_debug.h"
#include "aj_wsl_net.h"
#include "aj_wsl_wmi.h"
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
 * IANA assigned IPv6 multicast group for AllJoyn formatted as a structure
 */
static uint8_t AJ_IPV6_MCAST_GROUP2[16] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3a };


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
/*
 * Current socket thats blocked inside select
 */
static int selectSock;
static NetContext netContext = { INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET };
/*
 * Call this function from an interrupt context to unblock a select call
 * This only has an effect if select is in a blocking state, any other blocking
 * calls will be unaffected by this call
 */
void AJ_Net_Interrupted(void)
{
    AJ_WSL_NET_signal_interrupted(selectSock);
}

static AJ_Status CloseNetSock(AJ_NetSocket* netSock)
{
    NetContext* context = (NetContext*)netSock->rx.context;
    if (context) {
        if (context->tcpSock != INVALID_SOCKET) {
            AJ_WSL_NET_socket_close(context->tcpSock);
        }
        if (context->udpSock != INVALID_SOCKET) {
            AJ_WSL_NET_socket_close(context->udpSock);
        }
        if (context->udp6Sock != INVALID_SOCKET) {
            AJ_WSL_NET_socket_close(context->udp6Sock);
        }

        context->tcpSock = context->udpSock = context->udp6Sock = INVALID_SOCKET;
        memset(netSock, 0, sizeof(AJ_NetSocket));
    }

    return AJ_OK;
}

AJ_Status AJ_Net_Send(AJ_IOBuffer* buf)
{
    NetContext* context = (NetContext*) buf->context;
    int ret;
    size_t tx = AJ_IO_BUF_AVAIL(buf);

    AJ_InfoPrintf(("AJ_Net_Send(buf=0x%p)\n", buf));

    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        ret = AJ_WSL_NET_socket_send(context->tcpSock, buf->readPtr, tx, 0);
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

AJ_Status AJ_Net_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    AJ_Status status = AJ_OK;
    int16_t ret;
    AJ_Time timer;
    NetContext* context = (NetContext*) buf->context;
    size_t rx = AJ_IO_BUF_SPACE(buf);

    AJ_InfoPrintf(("AJ_Net_Recv(buf=0x%p, len=%ld., timeout=%ld.)\n", buf, len, timeout));

    assert(buf->direction == AJ_IO_BUF_RX);
    selectSock = context->tcpSock;
    AJ_InitTimer(&timer);
    ret = AJ_WSL_NET_socket_select(context->tcpSock, timeout);
    if (ret == -2) {
        // Select timed out
        return AJ_ERR_TIMEOUT;
    } else if (ret == -1) {
        // We were interrupted
        return AJ_ERR_INTERRUPTED;
    } else if (ret == 0) {
        // The socket was closed
        return AJ_ERR_READ;
    }
    // If we pass these checks there is data ready for receive
    timeout -= AJ_GetElapsedTime(&timer, TRUE);
    rx = min(rx, len);
    if (rx) {
        ret = AJ_WSL_NET_socket_recv(context->tcpSock, buf->writePtr, rx, timeout);
        if (ret == -1) {
            status = AJ_ERR_READ;
        } else if (ret == 0) {
            status = AJ_ERR_TIMEOUT;
        } else {
            buf->writePtr += ret;
        }
    }
//    AJ_InfoPrintf(("AJ_Net_Recv(): status=%s\n", AJ_StatusText(status)));

    return status;
}

static uint8_t rxData[1024];
static uint8_t txData[1024];

AJ_Status AJ_Net_Connect(AJ_NetSocket* netSock, uint16_t port, uint8_t addrType, const uint32_t* addr)
{
    int ret;

    AJ_InfoPrintf(("AJ_Net_Connect(netSock=0x%p, port=%d., addrType=%d., addr=0x%lx)\n", netSock, port, addrType, *addr));

    int tcpSock = AJ_WSL_NET_socket_open(WSL_AF_INET, WSL_SOCK_STREAM, 0);
    if (tcpSock == INVALID_SOCKET) {
        AJ_ErrPrintf(("AJ_Net_Connect(): socket() failed.  status=AJ_ERR_CONNECT\n"));
        return AJ_ERR_CONNECT;
    }
    if (addrType == AJ_ADDR_IPV4) {

    } else {
        //TODO: IPv6 connect. Alljoyn never uses IPv6 TCP but maybe in the future
    }
    ret = AJ_WSL_NET_socket_connect(tcpSock, BE32_TO_CPU(*addr), port, WSL_AF_INET);
    if (ret < 0) {
        //AJ_ErrPrintf(("AJ_Net_Connect(): connect() failed. errno=\"%s\", status=AJ_ERR_CONNECT\n", strerror(errno)));
        return AJ_ERR_CONNECT;
    } else {
        netContext.tcpSock = tcpSock;
        AJ_IOBufInit(&netSock->rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, &netContext);
        netSock->rx.recv = AJ_Net_Recv;
        AJ_IOBufInit(&netSock->tx, txData, sizeof(txData), AJ_IO_BUF_TX, &netContext);
        netSock->tx.send = AJ_Net_Send;
        AJ_InfoPrintf(("AJ_Net_Connect(): status=AJ_OK\n"));
        return AJ_OK;
    }

    return AJ_OK;
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
    CloseNetSock(netSock);
}

AJ_Status AJ_Net_SendTo(AJ_IOBuffer* buf)
{

    int ret;
    size_t tx = AJ_IO_BUF_AVAIL(buf);
    NetContext* context = (NetContext*) buf->context;
    AJ_InfoPrintf(("AJ_Net_SendTo(buf=0x%p)\n", buf));
    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        // Send out IPv4 multicast
        if (context->udpSock != INVALID_SOCKET) {
            ret = AJ_WSL_NET_socket_sendto(context->udpSock, buf->readPtr, tx, BE32_TO_CPU(AJ_IPV4_MCAST_GROUP), 9956, 0);
        }
        // now send to the IPv6 address
        if (context->udp6Sock != INVALID_SOCKET) {
            ret = AJ_WSL_NET_socket_sendto6(context->udp6Sock, buf->readPtr, tx, AJ_IPV6_MCAST_GROUP2, 9956, 0);
        }
        if (ret == -1) {
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

    AJ_Status status = AJ_OK;

    NetContext* context = (NetContext*) buf->context;
    int sock = context->udpSock;
    uint32_t poll = min(100, timeout / 2);
    size_t rx = AJ_IO_BUF_SPACE(buf);

    AJ_InfoPrintf(("AJ_Net_RecvFrom(buf=0x%p, len=%ld., timeout=%ld.)\n", buf, len, timeout));

    assert(buf->direction == AJ_IO_BUF_RX);
    int ret;
    while (1) {

        ret = AJ_WSL_NET_socket_recv(sock, buf->writePtr, rx, poll);

        if (ret == -1) {
            // Tried to read from an invalid socket
            return AJ_ERR_READ;
        }
        if (ret > 0) {
            buf->writePtr += ret;
            return AJ_OK;
        }
        if (timeout < 100) {
            AJ_ErrPrintf(("AJ_Net_RecvFrom(): select() timed out. status=AJ_ERR_TIMEOUT\n"));
            return AJ_ERR_TIMEOUT;
        }
        timeout -= 100;
        sock = (sock == context->udpSock) ? context->udp6Sock : context->udpSock;
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
const uint16_t rxDataMCastSize = 1454;
const uint16_t txDataMCastSize = 262;

#ifndef SO_REUSEPORT
#define SO_REUSEPORT SO_REUSEADDR
#endif


static int MCastUp4()
{
    int ret;
    int mcastSock;

    AJ_InfoPrintf(("MCastUp4()\n"));

    mcastSock = AJ_WSL_NET_socket_open(WSL_AF_INET, WSL_SOCK_DGRAM, 0);
    if (mcastSock == INVALID_SOCKET) {
        AJ_ErrPrintf(("MCastUp4(): socket() fails. status=AJ_ERR_READ\n"));
        return INVALID_SOCKET;
    }

    /*
     * Bind an ephemeral port
     */
    ret = AJ_WSL_NET_socket_bind(mcastSock, 0x00000000, AJ_EphemeralPort());
    /*
     * Join our multicast group
     */
    uint32_t optval[2] = { AJ_IPV4_MCAST_GROUP, AJ_INADDR_ANY };
    ret = AJ_WSL_NET_set_sock_options(mcastSock, WSL_IPPROTO_IP, WSL_ADD_MEMBERSHIP, sizeof(optval), (uint8_t*)&optval);
    if (ret < 0) {
        AJ_ErrPrintf(("MCastUp4(): setsockopt(IP_ADD_MEMBERSHIP) failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        AJ_WSL_NET_socket_close(mcastSock);
        return INVALID_SOCKET;
    }

    return mcastSock;

}

static int MCastUp6()
{
    int ret;
    int mcastSock;

    uint8_t gblAddr[16];
    uint8_t locAddr[16];
    uint8_t gwAddr[16];
    uint8_t gblExtAddr[16];
    uint32_t linkPrefix = 0;
    uint32_t glbPrefix = 0;
    uint32_t gwPrefix = 0;
    uint32_t glbExtPrefix = 0;
    uint16_t IP6_ADDR_ANY[8];
    memset(&IP6_ADDR_ANY, 0, 16);
    /*
     * We pass the current global IPv6 address into the sockopt for joining the multicast group.
     */
    AJ_WSL_ip6config(IPCONFIG_QUERY, &gblAddr, &locAddr, &gwAddr, &gblExtAddr, linkPrefix, glbPrefix, gwPrefix, glbExtPrefix);
    AJ_InfoPrintf(("Global Address:\n"));
    AJ_InfoPrintf(("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                   gblAddr[0], gblAddr[1], gblAddr[2], gblAddr[3],
                   gblAddr[4], gblAddr[5], gblAddr[6], gblAddr[7],
                   gblAddr[8], gblAddr[9], gblAddr[10], gblAddr[11],
                   gblAddr[12], gblAddr[13], gblAddr[14], gblAddr[15]));

    mcastSock = AJ_WSL_NET_socket_open(WSL_AF_INET6, WSL_SOCK_DGRAM, 0);

    if (mcastSock == INVALID_SOCKET) {
        AJ_ErrPrintf(("MCastUp6(): socket() fails. status=AJ_ERR_READ\n"));
        return INVALID_SOCKET;
    }
    ret = AJ_WSL_NET_socket_bind6(mcastSock, &IP6_ADDR_ANY, AJ_EphemeralPort());

    uint8_t optval[32];
    memcpy(&optval, &AJ_IPV6_MCAST_GROUP2, 16);
    memcpy(&optval[16], &gblAddr, 16);

    ret = AJ_WSL_NET_set_sock_options(mcastSock, WSL_IPPROTO_IP, WSL_JOIN_GROUP, 32, (uint8_t*)&optval);
    if (ret < 0) {
        AJ_ErrPrintf(("MCastUp4(): setsockopt(IP_ADD_MEMBERSHIP) failed. errno=\"%s\", status=AJ_ERR_READ\n", strerror(errno)));
        AJ_WSL_NET_socket_close(mcastSock);
        return INVALID_SOCKET;
    }

    return mcastSock;
}

AJ_Status AJ_Net_MCastUp(AJ_NetSocket* netSock)
{
    AJ_Status status = AJ_ERR_READ;
    netContext.udpSock = MCastUp4();
    netContext.udp6Sock = MCastUp6();

    if (netContext.udpSock != INVALID_SOCKET || netContext.udp6Sock != INVALID_SOCKET) {
        uint8_t* rxDataMCast = NULL;
        uint8_t* txDataMCast = NULL;

        rxDataMCast = AJ_Malloc(rxDataMCastSize);
        txDataMCast = AJ_Malloc(txDataMCastSize);
        if (!rxDataMCast || !txDataMCast) {
            return AJ_ERR_UNEXPECTED;
        }

        AJ_IOBufInit(&netSock->rx, rxDataMCast, rxDataMCastSize, AJ_IO_BUF_RX, &netContext);
        netSock->rx.recv = AJ_Net_RecvFrom;
        AJ_IOBufInit(&netSock->tx, txDataMCast, txDataMCastSize, AJ_IO_BUF_TX, &netContext);
        netSock->tx.send = AJ_Net_SendTo;
        status = AJ_OK;
    }

    return status;
}

void AJ_Net_MCastDown(AJ_NetSocket* netSock)
{
    int ret;
    NetContext* context = (NetContext*) netSock->rx.context;
    AJ_InfoPrintf(("AJ_Net_MCastDown(nexSock=0x%p)\n", netSock));

    if (context->udpSock != INVALID_SOCKET) {
        /*
         * Leave our multicast group
         */
        uint32_t optval[2] = { AJ_IPV4_MCAST_GROUP, AJ_INADDR_ANY };
        ret = AJ_WSL_NET_set_sock_options(context->udpSock, WSL_IPPROTO_IP, WSL_DROP_MEMBERSHIP, sizeof(optval), (uint8_t*)&optval);
        if (ret < 0) {
            AJ_ErrPrintf(("MCastDown4(): setsockopt(WSL_DROP_MEMBERSHIP) failed. errno=\"%d\", status=AJ_ERR_READ\n", ret));
            AJ_WSL_NET_socket_close(context->udpSock);
        }
        /* release the dynamically allocated buffers */
        AJ_Free(netSock->rx.bufStart);
        AJ_Free(netSock->tx.bufStart);
    }
    CloseNetSock(netSock);

}


AJ_Status AJ_Net_Up()
{
    AJ_InfoPrintf(("AJ_Net_Up()\n"));
    return AJ_OK;
}

void AJ_Net_Down()
{
    AJ_InfoPrintf(("AJ_Net_Up()\n"));
}

