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
#include "aj_serial.h"

#define BITRATE B115200
#define AJ_SERIAL_WINDOW_SIZE   4
#define AJ_SERIAL_ENABLE_CRC    1
#define AJ_SERIAL_PACKET_SIZE   1000 + AJ_SERIAL_HDR_LEN

AJ_Status AJ_Net_Send(AJ_IOBuffer* buf)
{
    AJ_Status ret;
    size_t tx = AJ_IO_BUF_AVAIL(buf);

    assert(buf->direction == AJ_IO_BUF_TX);

    if (tx > 0) {
        ret = AJ_SerialSend(buf->readPtr, tx);
        if (ret != AJ_OK) {
#ifndef NDEBUG
            fprintf(stderr, "AJ_SerialSend() failed: %u\n", ret);
#endif
            return AJ_ERR_WRITE;
        }
        buf->readPtr += tx;
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
    uint16_t recv = 0;

    assert(buf->direction == AJ_IO_BUF_RX);

    rx = min(rx, len);
    if (rx) {
        AJ_Status ret = AJ_SerialRecv(buf->writePtr, rx, timeout, &recv);
        if (ret != AJ_OK) {
#ifndef NDEBUG
            fprintf(stderr, "AJ_SerialRecv() failed: %u\n", ret);
#endif
            status = AJ_ERR_READ;
        } else {
            buf->writePtr += recv;
        }
    }
    return status;
}


static uint8_t rxData[1024];
static uint8_t txData[1024];

AJ_Status AJ_Net_Connect(AJ_NetSocket* netSock, uint16_t port, uint8_t addrType, const uint32_t* addr)
{
    int ret = 0;

    AJ_IOBufInit(&netSock->rx, rxData, sizeof(rxData), AJ_IO_BUF_RX, NULL);
    netSock->rx.recv = AJ_Net_Recv;
    AJ_IOBufInit(&netSock->tx, txData, sizeof(txData), AJ_IO_BUF_TX, NULL);
    netSock->tx.send = AJ_Net_Send;
    return AJ_OK;
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
    //TODO AJ_SerialShutdown
}

AJ_Status AJ_Net_SendTo(AJ_IOBuffer* buf)
{
    assert(0);
    return AJ_ERR_UNEXPECTED;
}

AJ_Status AJ_Net_RecvFrom(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    assert(0);
    return AJ_ERR_UNEXPECTED;
}

AJ_Status AJ_Net_MCastUp(AJ_NetSocket* netSock)
{
    assert(0);
    return AJ_ERR_UNEXPECTED;
}

void AJ_Net_MCastDown(AJ_NetSocket* netSock)
{
    assert(0);
    return AJ_ERR_UNEXPECTED;
}


AJ_Status AJ_Net_Up()
{
    AJ_Status status = AJ_SerialInit("/dev/ttyUSB0", BITRATE, AJ_SERIAL_WINDOW_SIZE, AJ_SERIAL_ENABLE_CRC, AJ_SERIAL_PACKET_SIZE);
    AJ_Sleep(3000);  // wait a while for the link configuration to complete
    return status;
}

void AJ_Net_Down()
{
}