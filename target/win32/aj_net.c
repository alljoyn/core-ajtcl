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

#include <Winsock2.h>
#include <Mswsock.h>

#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include <assert.h>
#include <stdio.h>
#include <time.h>

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


static void WinsockCheck()
{
    static uint8_t initialized = FALSE;
    if (!initialized) {
        WSADATA wsaData;
        WORD version = MAKEWORD(2, 0);
        int ret;
        AJ_InfoPrintf(("WinsockCheck\n"));

        ret = WSAStartup(version, &wsaData);
        if (ret) {
            AJ_ErrPrintf(("WSAStartup failed with error: %d\n", ret));
        } else {
            initialized = TRUE;
        }
    }
}

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

static AJ_Status AJ_Net_Send(AJ_IOBuffer* buf)
{
    DWORD ret;
    DWORD tx = AJ_IO_BUF_AVAIL(buf);

    AJ_InfoPrintf(("AJ_Net_Send(buf=0x%p)\n", buf));

    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        ret = send((SOCKET)buf->context, buf->readPtr, tx, 0);
        if (ret == SOCKET_ERROR) {
            AJ_ErrPrintf(("AJ_Net_Send(): send() failed. WSAGetLastError()=0x%x, status=AJ_ERR_WRITE\n", WSAGetLastError()));
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

static AJ_Status AJ_Net_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    AJ_Status status = AJ_OK;
    DWORD rx = AJ_IO_BUF_SPACE(buf);
    fd_set fds;
    int rc = 0;
    const struct timeval tv = { timeout / 1000, 1000 * (timeout % 1000) };

    AJ_InfoPrintf(("AJ_Net_Recv(buf=0x%p, len=%d., timeout=%d.)\n", buf, len, timeout));

    assert(buf->direction == AJ_IO_BUF_RX);

    FD_ZERO(&fds);
    FD_SET((SOCKET)buf->context, &fds);
    rc = select(1, &fds, NULL, NULL, &tv);
    if (rc == 0) {
        return AJ_ERR_TIMEOUT;
    }

    rx = min(rx, len);
    if (rx) {
        DWORD ret = recv((SOCKET)buf->context, buf->writePtr, rx, 0);
        if ((ret == SOCKET_ERROR) || (ret == 0)) {
            AJ_ErrPrintf(("AJ_Net_Recv(): recv() failed. WSAGetLastError()=0x%x, status=AJ_ERR_READ\n", WSAGetLastError()));
            status = AJ_ERR_READ;
        } else {
            buf->writePtr += ret;
        }
    }
    AJ_InfoPrintf(("AJ_Net_Recv(): status=%s\n", AJ_StatusText(status)));
    return status;
}

/*
 * Statically sized buffers for I/O
 */
static uint8_t rxData[1024];
static uint8_t txData[1024];

AJ_Status AJ_Net_Connect(AJ_NetSocket* netSock, uint16_t port, uint8_t addrType, const uint32_t* addr)
{
    DWORD ret;
    SOCKADDR_STORAGE addrBuf;
    socklen_t addrSize;
    SOCKET sock;

    AJ_InfoPrintf(("AJ_Net_Connect(nexSock=0x%p, port=%d., addrType=%d., addr=0x%p)\n", netSock, port, addrType, addr));

    /* Initialize Winsock, if not done already */
    WinsockCheck();

    memset(&addrBuf, 0, sizeof(addrBuf));

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        AJ_ErrPrintf(("AJ_Net_Connect(): invalid socket.  status=AJ_ERR_CONNECT\n"));
        return AJ_ERR_CONNECT;
    }
    if (addrType == AJ_ADDR_IPV4) {
        struct sockaddr_in* sa = (struct sockaddr_in*)&addrBuf;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr.s_addr = *addr;
        addrSize = sizeof(*sa);
        AJ_InfoPrintf(("AJ_Net_Connect(): Connect to \"%s:%u\"\n", inet_ntoa(sa->sin_addr), port));;
    } else {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)&addrBuf;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        memcpy(sa->sin6_addr.s6_addr, addr, sizeof(sa->sin6_addr.s6_addr));
        addrSize = sizeof(*sa);
    }
    ret = connect(sock, (struct sockaddr*)&addrBuf, addrSize);
    if (ret == SOCKET_ERROR) {
        AJ_ErrPrintf(("AJ_Net_Connect(): connect() failed. WSAGetLastError()=0x%x, status=AJ_ERR_CONNECT\n", WSAGetLastError()));
        closesocket(sock);
        return AJ_ERR_CONNECT;
    } else {
        AJ_IOBufInit(&netSock->rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, (void*)sock);
        netSock->rx.recv = AJ_Net_Recv;
        AJ_IOBufInit(&netSock->tx, txData, sizeof(txData), AJ_IO_BUF_TX, (void*)sock);
        netSock->tx.send = AJ_Net_Send;
        AJ_InfoPrintf(("AJ_Net_Connect(): status=AJ_OK\n"));
        return AJ_OK;
    }
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
    SOCKET sock = (SOCKET)netSock->rx.context;

    AJ_InfoPrintf(("AJ_Net_Disconnect(nexSock=0x%p)\n", netSock));

    if (sock) {
        shutdown(sock, 0);
        closesocket(sock);
        memset(netSock, 0, sizeof(AJ_NetSocket));
    }
}

typedef struct {
    SOCKET sock;
    int family;

    struct in_addr v4_bcast;
    uint8_t has_mcast4;
} mcast_info_t;

static mcast_info_t* McastSocks = NULL;
static size_t NumMcastSocks = 0;

static AJ_Status AJ_Net_SendTo(AJ_IOBuffer* buf)
{
    DWORD ret;
    DWORD tx = AJ_IO_BUF_AVAIL(buf);
    int numWrites = 0;

    AJ_InfoPrintf(("AJ_Net_SendTo(buf=0x%p)\n", buf));

    assert(buf->direction == AJ_IO_BUF_TX);
    assert(NumMcastSocks > 0);

    if (tx > 0) {
        size_t i;

        // our router (hopefully) lives on one of the networks but we don't know which one.
        // send the WhoHas packet to all of them.
        for (i = 0; i < NumMcastSocks; ++i) {
            SOCKET sock = McastSocks[i].sock;
            int family = McastSocks[i].family;

            if (family == AF_INET6) {
                struct sockaddr_in6 sin6;
                memset(&sin6, 0, sizeof(struct sockaddr_in6));
                sin6.sin6_family = AF_INET6;
                sin6.sin6_port = htons(AJ_UDP_PORT);
                inet_pton(AF_INET6, AJ_IPV6_MULTICAST_GROUP, &sin6.sin6_addr);
                ret = sendto(sock, buf->readPtr, tx, 0, (struct sockaddr*) &sin6, sizeof(struct sockaddr_in6));
                if (ret == SOCKET_ERROR) {
                    AJ_ErrPrintf(("AJ_Net_SendTo(): sendto() failed (IPV6). WSAGetLastError()=0x%x\n", WSAGetLastError()));
                } else {
                    ++numWrites;
                }
            } else {
                // try sending IPV4 multicast
                if (McastSocks[i].has_mcast4) {
                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_port = htons(AJ_UDP_PORT);
                    inet_pton(AF_INET, AJ_IPV4_MULTICAST_GROUP, &sin.sin_addr);
                    memset(&sin.sin_zero, 0, sizeof(sin.sin_zero));

                    ret = sendto(sock, buf->readPtr, tx, 0, (struct sockaddr*) &sin, sizeof(struct sockaddr_in));
                    if (ret == SOCKET_ERROR) {
                        AJ_ErrPrintf(("AJ_Net_SendTo(): sendto() failed (IPV4). WSAGetLastError()=0x%x\n", WSAGetLastError()));
                    } else {
                        ++numWrites;
                    }
                }

                // try sending subnet broadcast
                if (McastSocks[i].v4_bcast.s_addr) {
                    struct sockaddr_in bsin;
                    bsin.sin_family = AF_INET;
                    bsin.sin_port = htons(AJ_UDP_PORT);
                    bsin.sin_addr.s_addr = McastSocks[i].v4_bcast.s_addr;
                    ret = sendto(sock, buf->readPtr, tx, 0, (struct sockaddr*) &bsin, sizeof(struct sockaddr_in));
                    if (ret == SOCKET_ERROR) {
                        AJ_ErrPrintf(("AJ_Net_SendTo(): sendto() failed (bcast). WSAGetLastError()=0x%x\n", WSAGetLastError()));
                    } else {
                        ++numWrites;
                    }
                }
            }
        }

        if (numWrites == 0) {
            AJ_ErrPrintf(("AJ_Net_SendTo(): Did not sendto() at least one socket.  status=AJ_ERR_WRITE\n"));
            return AJ_ERR_WRITE;
        }
        buf->readPtr += ret;
    }
    AJ_IO_BUF_RESET(buf);
    AJ_InfoPrintf(("AJ_Net_SendTo(): status=AJ_OK\n"));
    return AJ_OK;
}

static AJ_Status AJ_Net_RecvFrom(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    AJ_Status status;
    DWORD ret;
    DWORD rx = AJ_IO_BUF_SPACE(buf);
    fd_set fds;
    size_t rc = 0;
    size_t i;
    const struct timeval tv = { timeout / 1000, 1000 * (timeout % 1000) };
    SOCKET sock;

    AJ_InfoPrintf(("AJ_Net_RecvFrom(buf=0x%p, len=%d., timeout=%d.)\n", buf, len, timeout));

    assert(buf->direction == AJ_IO_BUF_RX);
    assert(NumMcastSocks > 0);

    // one per interface
    FD_ZERO(&fds);
    for (i = 0; i < NumMcastSocks; ++i) {
        SOCKET sock = McastSocks[i].sock;
        FD_SET(sock, &fds);
    }

    rc = select(NumMcastSocks, &fds, NULL, NULL, &tv);
    if (rc == 0) {
        AJ_InfoPrintf(("AJ_Net_RecvFrom(): select() timed out. status=AJ_ERR_TIMEOUT\n"));
        return AJ_ERR_TIMEOUT;
    } else if (rc < 0) {
        AJ_ErrPrintf(("AJ_Net_RecvFrom(): select() failed. WSAGetLastError()=0x%x, status=AJ_ERR_READ\n", WSAGetLastError()));
        return AJ_ERR_READ;
    }

    // we sent the WhoHas packet out on ALL multicast WIFI interfaces
    // now we need to listen to all of them for a reply
    // ignore multiple replies; only consider the first one to arrive
    rx = min(rx, len);
    for (i = 0; i < NumMcastSocks; ++i) {
        if (FD_ISSET(McastSocks[i].sock, &fds)) {
            sock = McastSocks[i].sock;
            break;
        }
    }

    if (sock != INVALID_SOCKET) {
        ret = recvfrom(sock, buf->writePtr, rx, 0, NULL, 0);
        if (ret == SOCKET_ERROR) {
            AJ_ErrPrintf(("AJ_Net_RecvFrom(): recvfrom() failed. WSAGetLastError()=0x%x, status=AJ_ERR_READ\n", WSAGetLastError()));
            status = AJ_ERR_READ;
        } else {
            buf->writePtr += ret;
            status = AJ_OK;
        }
    } else {
        AJ_ErrPrintf(("AJ_Net_RecvFrom(): invalid socket.  status=AJ_ERR_READ\n"));
        status = AJ_ERR_READ;
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

static void Mcast6Up()
{
    char iface_buffer[sizeof(IP_ADAPTER_ADDRESSES) * 150];
    PIP_ADAPTER_ADDRESSES interfaces = (PIP_ADAPTER_ADDRESSES) iface_buffer;
    DWORD num_bytes = sizeof(iface_buffer);

    // of course, doing this for IPV6 is completely different from the IPV4 version.
    if (ERROR_SUCCESS != GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, interfaces, &num_bytes)) {
        AJ_ErrPrintf(("Mcast6Up(): GetAdaptersAddresses failed. WSAGetLastError()=%0x%x\n", WSAGetLastError()));
        return;
    }

    for (; interfaces != NULL; interfaces = interfaces->Next) {
        int ret = 0;
        struct sockaddr_in6 addr;
        struct ipv6_mreq mreq6;


        mcast_info_t new_sock;
        new_sock.sock = INVALID_SOCKET;
        new_sock.family = AF_INET6;
        new_sock.has_mcast4 = FALSE;
        new_sock.v4_bcast.s_addr = 0;


        memset(&mreq6, 0, sizeof(struct ipv6_mreq));

        if (interfaces->OperStatus != IfOperStatusUp || interfaces->NoMulticast) {
            continue;
        }

        memcpy(&addr, interfaces->FirstUnicastAddress->Address.lpSockaddr, sizeof(struct sockaddr_in6));

        // create a socket
        new_sock.sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (new_sock.sock == INVALID_SOCKET) {
            AJ_ErrPrintf(("Mcast6Up(): socket() failed. WSAGetLastError()=0x%x\n", WSAGetLastError()));
            continue;
        }

        // bind the socket to the address with ephemeral port
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(0);

        ret = bind(new_sock.sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in6));
        if (ret == SOCKET_ERROR) {
            AJ_ErrPrintf(("Mcast6Up(): bind() failed. WSAGetLastError()=0x%x\n", WSAGetLastError()));
            closesocket(new_sock.sock);
            new_sock.sock = INVALID_SOCKET;
            continue;
        }

        // because routers are advertised silently, the reply will be unicast
        // however, Windows forces us to join the multicast group before we can broadcast our WhoHas packets
        inet_pton(AF_INET6, AJ_IPV6_MULTICAST_GROUP, &mreq6.ipv6mr_multiaddr);
        mreq6.ipv6mr_interface = interfaces->IfIndex;

        ret = setsockopt(new_sock.sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*) &mreq6, sizeof(mreq6));
        if (ret == SOCKET_ERROR) {
            AJ_ErrPrintf(("Mcast6Up(): setsockopt(IP_ADD_MEMBERSHIP) failed. WSAGetLastError()=0x%x\n", WSAGetLastError()));
            closesocket(new_sock.sock);
            new_sock.sock = INVALID_SOCKET;
            continue;
        }

        if (new_sock.sock != INVALID_SOCKET) {
            NumMcastSocks++;
            McastSocks = realloc(McastSocks, NumMcastSocks * sizeof(mcast_info_t));
            memcpy(&McastSocks[NumMcastSocks - 1], &new_sock, sizeof(mcast_info_t));
        }
    }
}


static void Mcast4Up()
{
    int ret = 0;
    INTERFACE_INFO interfaces[150];
    DWORD num_bytes, num_ifaces;
    SOCKET tmp_sock;
    uint32_t i = 0;

    tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp_sock == INVALID_SOCKET) {
        AJ_ErrPrintf(("Mcast4Up(): socket failed. WSAGetLastError()=%0x%x\n", WSAGetLastError()));
        return;
    }

    if (SOCKET_ERROR == WSAIoctl(tmp_sock, SIO_GET_INTERFACE_LIST, 0, 0, &interfaces, sizeof(interfaces), &num_bytes, 0, 0)) {
        AJ_ErrPrintf(("Mcast4Up(): WSAIoctl failed. WSAGetLastError()=%0x%x\n", WSAGetLastError()));
        return;
    }


    closesocket(tmp_sock);
    num_ifaces = num_bytes / sizeof(INTERFACE_INFO);

    for (i = 0; i < num_ifaces; ++i) {
        LPINTERFACE_INFO info = &interfaces[i];
        struct sockaddr_in* addr =  &info->iiAddress.AddressIn;
        mcast_info_t new_sock;

        new_sock.sock = INVALID_SOCKET;
        new_sock.family = AF_INET;
        new_sock.has_mcast4 = FALSE;
        new_sock.v4_bcast.s_addr = 0;

        if (!(info->iiFlags & IFF_UP)) {
            continue;
        }

        // create a socket
        new_sock.sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (new_sock.sock == INVALID_SOCKET) {
            AJ_ErrPrintf(("Mcast4Up(): socket() failed. WSAGetLastError()=0x%x\n", WSAGetLastError()));
        }

        // if this address supports IPV4 broadcast, calculate the subnet bcast address and save it
        if (info->iiFlags & IFF_BROADCAST) {
            int bcast = 1;
            ret = setsockopt(new_sock.sock, SOL_SOCKET, SO_BROADCAST, (void*) &bcast, sizeof(bcast));
            if (ret != 0) {
                AJ_ErrPrintf(("Mcast4Up(): setsockopt(SO_BROADCAST) failed. WSAGetLastError()=0x%x\n", WSAGetLastError()));
                closesocket(new_sock.sock);
                new_sock.sock = INVALID_SOCKET;
                continue;
            }

            new_sock.v4_bcast.s_addr = info->iiAddress.AddressIn.sin_addr.s_addr | ~(info->iiNetmask.AddressIn.sin_addr.s_addr);
        }

        // and if it supports multicast, join the IPV4 mcast group
        if (info->iiFlags & IFF_MULTICAST) {
            struct ip_mreq mreq;
            struct sockaddr_in sin;
            memset(&mreq, 0, sizeof(struct ip_mreq));

            // bind the socket to the address with ephemeral port
            sin.sin_family = AF_INET;
            sin.sin_port = htons(0);
            memcpy(&sin, addr, sizeof(struct sockaddr_in));

            ret = bind(new_sock.sock, (struct sockaddr*) &sin, sizeof(sin));
            if (ret == SOCKET_ERROR) {
                AJ_ErrPrintf(("Mcast4Up(): bind() failed. WSAGetLastError()=0x%x\n", WSAGetLastError()));
                closesocket(new_sock.sock);
                new_sock.sock = INVALID_SOCKET;
                continue;
            }

            // because routers are advertised silently, the reply will be unicast
            // however, Windows forces us to join the multicast group before we can broadcast our WhoHas packets
            inet_pton(AF_INET, AJ_IPV4_MULTICAST_GROUP, &mreq.imr_multiaddr);
            memcpy(&mreq.imr_interface, &sin.sin_addr, sizeof(struct in_addr));
            ret = setsockopt(new_sock.sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq));
            if (ret == SOCKET_ERROR) {
                AJ_ErrPrintf(("Mcast4Up(): setsockopt(IP_ADD_MEMBERSHIP) failed. WSAGetLastError()=0x%x\n", WSAGetLastError()));
                closesocket(new_sock.sock);
                new_sock.sock = INVALID_SOCKET;
                continue;
            }

            new_sock.has_mcast4 = TRUE;
        }

        if (new_sock.sock != INVALID_SOCKET) {
            NumMcastSocks++;
            McastSocks = realloc(McastSocks, NumMcastSocks * sizeof(mcast_info_t));
            memcpy(&McastSocks[NumMcastSocks - 1], &new_sock, sizeof(mcast_info_t));
        }
    }
}


AJ_Status AJ_Net_MCastUp(AJ_NetSocket* netSock)
{
    AJ_Status status = AJ_OK;
    // bring up WinSock
    WinsockCheck();

    AJ_InfoPrintf(("AJ_Net_MCastUp(nexSock=0x%p)\n", netSock));

    Mcast4Up();
    Mcast6Up();

    // if we don't have at least one good socket for multicast, error
    if (NumMcastSocks == 0) {
        AJ_ErrPrintf(("AJ_Net_MCastUp(): No sockets found.  status=AJ_ERR_READ\n"));
        status = AJ_ERR_READ;
    }


    if (status == AJ_OK) {
        AJ_IOBufInit(&netSock->rx, rxDataMCast, sizeof(rxDataMCast), AJ_IO_BUF_RX, (void*) McastSocks);
        netSock->rx.recv = AJ_Net_RecvFrom;
        AJ_IOBufInit(&netSock->tx, txDataMCast, sizeof(txDataMCast), AJ_IO_BUF_TX, (void*) McastSocks);
        netSock->tx.send = AJ_Net_SendTo;
    }

    AJ_InfoPrintf(("AJ_Net_MCastUp(): status=%s\n", AJ_StatusText(status)));
    return status;
}

void AJ_Net_MCastDown(AJ_NetSocket* netSock)
{
    size_t i;
    AJ_InfoPrintf(("AJ_Net_MCastDown(nexSock=0x%p)\n", netSock));

    /*
     * Leave our multicast group
     */
    for (i = 0; i < NumMcastSocks; ++i) {
        SOCKET sock = McastSocks[i].sock;

        if (McastSocks[i].family == AF_INET) {
            struct ip_mreq mreq;
            inet_pton(AF_INET, AJ_IPV4_MULTICAST_GROUP, &mreq.imr_multiaddr);
            mreq.imr_interface.s_addr = INADDR_ANY;
            setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*) &mreq, sizeof(mreq));
        } else if (McastSocks[i].family == AF_INET6) {
            struct ipv6_mreq mreq6;
            inet_pton(AF_INET6, AJ_IPV6_MULTICAST_GROUP, &mreq6.ipv6mr_multiaddr);
            mreq6.ipv6mr_interface = 0;
            setsockopt(sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char*) &mreq6, sizeof(mreq6));
        }


        shutdown(sock, 0);
        closesocket(sock);
    }

    NumMcastSocks = 0;
    free(McastSocks);
    McastSocks = NULL;
    memset(netSock, 0, sizeof(AJ_NetSocket));
}
