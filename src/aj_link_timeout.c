/**
 * @file
 */
/******************************************************************************
 *  * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
#include <aj_link_timeout.h>

/*
 * Bus link timeout related
 */
#define AJ_MIN_BUS_LINK_TIMEOUT  40      /** The minimum link timeout value for the bus link. No probe packets are sent during this period even if no activities on the link. The unit is second */
#define AJ_BUS_LINK_PING_TIMEOUT 5       /** The time period in which the probe request packet should be acked. The unit is second */
#define AJ_MAX_LINK_PING_PACKETS 3       /** The maximum number of allowed outstanding probe request packets unacked. */

typedef struct _AJ_BusLinkWatcher {
    uint8_t numOfPingTimedOut;           /**< Number of probe request packets already sent but unacked */
    uint8_t linkTimerInited;             /**< If timer linkTimer is inited */
    uint8_t pingTimerInited;             /**< If timer pingTimer is inited */
    AJ_Time linkTimer;                   /**< Timer for tracking activities over the link to the daemon bus */
    AJ_Time pingTimer;                   /**< Timer for tracking probe request packets */
} AJ_BusLinkWatcher;

static uint32_t busLinkTimeout;          /**< Timeout value for the link to the daemon bus */
static AJ_BusLinkWatcher busLinkWatcher; /**< Data structure that maintains information for tracking the link to the daemon bus */

/**
 * Forward declaration
 */
AJ_Status AJ_SendLinkProbeReq(AJ_BusAttachment* bus);

AJ_Status AJ_SetBusLinkTimeout(AJ_BusAttachment* bus, uint32_t timeout)
{
    if (!timeout) return AJ_ERR_FAILURE;
    timeout = (timeout > AJ_MIN_BUS_LINK_TIMEOUT) ? timeout : AJ_MIN_BUS_LINK_TIMEOUT;
    busLinkTimeout = timeout * 1000;
    return AJ_OK;
}

void AJ_NotifyLinkActive()
{
    memset(&busLinkWatcher, 0, sizeof(AJ_BusLinkWatcher));
}

AJ_Status AJ_BusLinkStateProc(AJ_BusAttachment* bus)
{
    AJ_Status status = AJ_OK;
    if (busLinkTimeout) {
        if (!busLinkWatcher.linkTimerInited) {
            busLinkWatcher.linkTimerInited = TRUE;
            AJ_InitTimer(&(busLinkWatcher.linkTimer));
        } else {
            uint32_t eclipse = AJ_GetElapsedTime(&(busLinkWatcher.linkTimer), TRUE);
            if (eclipse >= busLinkTimeout) {
                if (!busLinkWatcher.pingTimerInited) {
                    busLinkWatcher.pingTimerInited = TRUE;
                    AJ_InitTimer(&(busLinkWatcher.pingTimer));
                    if (AJ_OK != AJ_SendLinkProbeReq(bus)) {
                        AJ_Printf("Error: Fail to send probe reqeust!\n");
                    }
                } else {
                    eclipse = AJ_GetElapsedTime(&(busLinkWatcher.pingTimer), TRUE);
                    if (eclipse >=  AJ_BUS_LINK_PING_TIMEOUT) {
                        if (++busLinkWatcher.numOfPingTimedOut < AJ_MAX_LINK_PING_PACKETS) {
                            AJ_InitTimer(&(busLinkWatcher.pingTimer));
                            if (AJ_OK != AJ_SendLinkProbeReq(bus)) {
                                AJ_Printf("Error: Fail to send probe reqeust!\n");
                            }
                        } else {
                            status = AJ_ERR_LINK_TIMEOUT;
                            // stop sending probe messages until next link timeout event
                            memset(&busLinkWatcher, 0, sizeof(AJ_BusLinkWatcher));
                        }
                    }
                }
            }
        }
    }
    return status;
}

AJ_Status AJ_SendLinkProbeReq(AJ_BusAttachment* bus)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalSignal(bus, &msg, AJ_SIGNAL_PROBE_REQ, AJ_BusDestination, 0, 0, 0);
    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    return status;
}
