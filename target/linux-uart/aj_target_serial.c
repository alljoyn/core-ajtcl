/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
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
#include "aj_status.h"
#include "aj_serial_rx.h"
#include "aj_serial_tx.h"
#include "aj_debug.h"

#include <signal.h>
#include <sys/types.h>

#ifdef AJ_DEBUG_SERIAL_TARGET
#define AJ_DebugDumpSerialRX(a, b, c) AJ_DumpBytes(a, b, c)
#define AJ_DebugDumpSerialTX(a, b, c) AJ_DumpBytes(a, b, c)
#else
#define AJ_DebugDumpSerialRX(a, b, c)
#define AJ_DebugDumpSerialTX(a, b, c)
#endif


int g_fdRead;

static struct sigaction saHandler;

void AJ_Serial_SignalHandlerIO(int status)
{
    //Disable interrupt
    sigaction(SIGIO, NULL, &saHandler);
    uint8_t buf[128];
    int16_t bytes;

    fd_set fds;
    int maxFd = -1;
    int rc = 0;
    struct timeval tv = { 0, 0 };

    FD_ZERO(&fds);
    FD_SET((int)g_fdRead, &fds);
    maxFd = max(maxFd, g_fdRead);

    rc = select(maxFd + 1, &fds, NULL, NULL, &tv);
    if (rc > 0) {
        bytes = read(g_fdRead, buf, sizeof(buf));
        if (bytes < 0) {
            AJ_Printf("Error reading!!!\n");
        } else if (bytes > 0) {
            AJ_DebugDumpSerialRX("AJ_UART_Rx", buf, bytes);
            OI_UART_RxComplete(buf, bytes);
        }
    }
    //Re-enable interrupt
    sigaction(SIGIO, &saHandler, NULL);

}

/**
 * This function initialized the UART piece of the transport.
 */
AJ_Status AJ_SerialTargetInit(const char* ttyName, uint16_t bitRate)
{
    AJ_Printf("AJ_SerialTargetInit %s\n", ttyName);
    struct termios tioNew;
    memset(&tioNew, 0, sizeof(tioNew));
    /// 115200 - 8 - E - 1
    tioNew.c_iflag = INPCK;
    tioNew.c_cflag = bitRate | CS8 | CLOCAL | CREAD | PARENB;
    tioNew.c_cc[VMIN] = 1; // 0 means it is ok to return 0 bytes on read.


    struct termios tioOriginalRead;

    g_fdRead = open(ttyName, O_RDWR | O_NOCTTY);
    if (g_fdRead < 0) {
        AJ_Printf("Failed to open read tty\n");
        return(-1);
    }

    // save the current serial port settings
    tcgetattr(g_fdRead, &tioOriginalRead);

    // toss out any waiting data.
    tcflush(g_fdRead, TCIOFLUSH);
    tcsetattr(g_fdRead, TCSANOW, &tioNew);
    tcflush(g_fdRead, TCIOFLUSH);

    // set up a signal handler to do something when serial port data arrives
    memset(&saHandler, 0, sizeof(saHandler));
    saHandler.sa_handler = AJ_Serial_SignalHandlerIO;
    sigemptyset(&saHandler.sa_mask);
    sigaction(SIGIO, &saHandler, NULL);

    fcntl(g_fdRead, F_SETOWN, getpid()); // let this process receive SIGIO.
    fcntl(g_fdRead, F_SETFL, FASYNC); // let things happen async

    return AJ_OK;
}



AJ_Status AJ_UART_Tx(uint8_t* buffer, uint16_t len)
{
    AJ_DebugDumpSerialTX("AJ_UART_Tx", buffer, len);
    write(g_fdRead, buffer, len);
    return AJ_OK;
}



void OI_HCIIfc_DeviceHasBeenReset(void)
{
    //stubbed out.
// perhaps we should close and reopen the UART?
}


char* OI_HciDataTypeText(uint8_t hciDataType)
{
    switch (hciDataType) {
    case AJ_SERIAL_DATA:      return("ACL DATA");

    case AJ_SERIAL_ACK:       return("H5 ACK");

    case AJ_SERIAL_CTRL:      return("H5 LINK CONTROL");
    }
    return("unknown");
}

uint8_t volatile g_SendCompleted = 0;

void WaitForAck(void)
{
    AJ_Printf("WaitForAck\n");

    // busy wait until there is some data.
    while (g_SendCompleted == 0) {
        usleep(1000);
        continue;
    }
    g_SendCompleted = 0;
}

void OI_HCIIfc_SendCompleted(uint8_t sendType,
                             AJ_Status status)
{
    // transport layer is ready, use this function to notify the upper layers
    AJ_Printf("OI_HCIIfc_SendCompleted senstype:%d status %u\n", sendType, status);
    g_SendCompleted = 1;
}

