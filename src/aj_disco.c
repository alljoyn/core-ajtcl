/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012-2013, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE DISCO

#include "aj_target.h"
#include "aj_status.h"
#include "aj_util.h"
#include "aj_net.h"
#include "aj_disco.h"
#include "aj_debug.h"
#include "aj_config.h"
/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgDISCO = 0;
#endif

typedef struct _NSHeader {
    uint8_t version;
    uint8_t qCount;
    uint8_t aCount;
    uint8_t ttl;
    uint8_t flags;
    uint8_t nameCount;
} NSHeader;

/*
 * Message V1 flag definitions
 */
#define U6_FLAG 0x01
#define R6_FLAG 0x02
#define U4_FLAG 0x04
#define R4_FLAG 0x08
#define C_FLAG  0x10
#define G_FLAG  0x20

#define MSG_TYPE(flags) ((flags) & 0xC0)

#define WHO_HAS_MSG   0x80
#define IS_AT_MSG     0x40

#define MSG_VERSION(flags)  ((flags) & 0x0F)

#define MSG_V0 0x00
#define MSG_V1 0x01
#define NSV_V1 0x10

static AJ_Status ComposeWhoHas(AJ_IOBuffer* txBuf, const char* prefix)
{
    size_t preLen = strlen(prefix);
    NSHeader* hdr = (NSHeader*)txBuf->writePtr;
    uint8_t* p = txBuf->writePtr + 6;
    size_t outLen = (6 + preLen + 2);

    AJ_InfoPrintf(("ComposeWhoHas(txbuf=0x%p, prefix=\"%s\")\n", txBuf, prefix));

    if (outLen > AJ_IO_BUF_SPACE(txBuf)) {
        AJ_ErrPrintf(("ComposeWhoHas(): AJ_ERR_RESOURCES\n"));
        return AJ_ERR_RESOURCES;
    }
    hdr->version = MSG_V1 | NSV_V1;
    hdr->qCount = 1;
    hdr->aCount = 0;
    hdr->ttl = 0;
    hdr->flags = WHO_HAS_MSG;
    hdr->nameCount = 1;
    *p++ = (uint8_t)(preLen + 1);
    memcpy(p, prefix, preLen);
    /*
     * Tack wild-card onto the end of the name to indicate it's prefix
     */
    p[preLen] = '*';
    txBuf->writePtr += outLen;
    return AJ_OK;
}

static AJ_Status ParseIsAt(AJ_IOBuffer* rxBuf, const char* prefix, AJ_Service* service)
{
    AJ_Status status = AJ_ERR_NO_MATCH;
    size_t preLen = strlen(prefix);
    NSHeader* hdr = (NSHeader*)rxBuf->readPtr;
    uint32_t len = AJ_IO_BUF_AVAIL(rxBuf);
    uint8_t* p = rxBuf->readPtr + 4;
    uint8_t* eod = (uint8_t*)hdr + len;

    AJ_InfoPrintf(("ParseIsAt(rxbuf=0x%p, prefix=\"%s\", service=0x%p)\n", rxBuf, prefix, service));

    service->addrTypes = 0;

    /*
     * Silently ignore versions we don't know how to parse
     */
    if (MSG_VERSION(hdr->version) != MSG_V1) {
        return status;
    }
    /*
     * Questions come in first - we currently ignore them
     */
    while (hdr->qCount--) {
        uint8_t flags = *p++;
        uint8_t nameCount = *p++;
        /*
         * Questions must be WHO_HAS messages
         */
        if (MSG_TYPE(flags) != WHO_HAS_MSG) {
            AJ_InfoPrintf(("ParseIsAt(): AJ_ERR_INVALID\n"));
            return AJ_ERR_INVALID;
        }
        while (nameCount--) {
            uint8_t sz = *p++;
            p += sz;
            if (p > eod) {
                AJ_InfoPrintf(("ParseIsAt(): AJ_ERR_END_OF_DATA\n"));
                status = AJ_ERR_END_OF_DATA;
                goto Exit;
            }
        }
    }
    /*
     * Now the answers - this is what we are looking for
     */
    while (hdr->aCount--) {
        uint8_t flags = *p++;
        uint8_t nameCount = *p++;
        /*
         * Answers must be IS_AT messages
         */
        if (MSG_TYPE(flags) != IS_AT_MSG) {
            AJ_InfoPrintf(("ParseIsAt(): AJ_ERR_INVALID\n"));
            return AJ_ERR_INVALID;
        }
        /*
         * Must be reliable IPV4 or IPV6
         */
        if (!(flags & (R4_FLAG | R6_FLAG))) {
            return status;
        }
        /*
         * Get transport mask
         */
        service->transportMask = (p[0] << 8) | p[1];
        p += 2;
        /*
         * Decode addresses
         */
        if (flags & R4_FLAG) {
            memcpy(&service->ipv4, p, sizeof(service->ipv4));
            p += sizeof(service->ipv4);
            service->ipv4port = (p[0] << 8) | p[1];
            p += 2;
            service->addrTypes |= AJ_ADDR_IPV4;
        }
        if (flags & U4_FLAG) {
            p += sizeof(service->ipv4) + 2;
        }
        if (flags & R6_FLAG) {
            memcpy(&service->ipv6, p, sizeof(service->ipv6));
            p += sizeof(service->ipv6);
            service->ipv6port = (p[0] << 8) | p[1];
            p += 2;
            service->addrTypes |= AJ_ADDR_IPV6;
        }
        if (flags & U6_FLAG) {
            p += sizeof(service->ipv6) + 2;
        }
        /*
         * Skip guid if it's present
         */
        if (flags & G_FLAG) {
            uint8_t sz = *p++;
            len -= 1 + sz;
            p += sz;
        }
        if (p >= eod) {
            AJ_InfoPrintf(("ParseIsAt(): AJ_ERR_END_OF_DATA\n"));
            return AJ_ERR_END_OF_DATA;
        }
        /*
         * Iterate over the names
         */
        while (nameCount--) {
            uint8_t sz = *p++;
            {
                char sav = p[sz];
                p[sz] = 0;
                AJ_InfoPrintf(("ParseIsAt(): Found \"%s\" IP 0x%x\n", p, service->addrTypes));
                p[sz] = sav;
            }
            if ((preLen <= sz) && (memcmp(p, prefix, preLen) == 0)) {
                status = AJ_OK;
                goto Exit;
            }
            p += sz;
            if (p > eod) {
                status = AJ_ERR_END_OF_DATA;
                AJ_InfoPrintf(("ParseIsAt(): AJ_ERR_END_OF_DATA\n"));
                goto Exit;
            }
        }
    }

Exit:
    return status;
}
/*
 * Function for determining whether or not to send a WHO-HAS packet. The algorithm
 * will send WHO-HAS packets every second for AJ_DISCOVER_ATTEMPTS seconds, then wait
 * AJ_FIRST_BACKOFF_TIME seconds and send another, then wait
 * AJ_SECOND_BACKOFF_TIME seconds and send another, then send WHO_HAS's every
 * AJ_THIRD_BACKOFF_TIME seconds until the timeout passed into AJ_Discover() expires
 */
static uint8_t sendDiscovery(uint32_t discoverAttempts, AJ_Time* discoverTimer)
{
    uint32_t waitPeriod;
    // Initial burst discovery
    if (discoverAttempts < AJ_DISCOVER_ATTEMPTS) {
        return TRUE;
    } else {
        //Decide to send a WHO-HAS packet based on the three back-off constants
        switch (discoverAttempts) {
        case (AJ_DISCOVER_ATTEMPTS):
        case (AJ_DISCOVER_ATTEMPTS + 1):
            waitPeriod = AJ_FIRST_BACKOFF_TIME;
            break;

        case (AJ_DISCOVER_ATTEMPTS + 2):
            waitPeriod = AJ_SECOND_BACKOFF_TIME;
            break;

        case (AJ_DISCOVER_ATTEMPTS + 3):
        default:
            waitPeriod = AJ_THIRD_BACKOFF_TIME;
            break;
        }
        if (AJ_GetElapsedTime(discoverTimer, TRUE) < waitPeriod) {
            return FALSE;
        } else {
            AJ_InitTimer(discoverTimer);
            return TRUE;
        }
    }
}
AJ_Status AJ_Discover(const char* prefix, AJ_Service* service, uint32_t timeout)
{
    AJ_Status status;
    uint32_t discoverAttempts = 0;
    AJ_Time discoverTimer;
    AJ_Time stopwatch;
    AJ_Time recvStopWatch;
    AJ_NetSocket sock;

    AJ_InfoPrintf(("AJ_Discover(prefix=\"%s\", service=0x%p, timeout=%d.)\n", prefix, service, timeout));

    /*
     * Initialize the timers
     * stopwatch for the overall discovery timeout
     * discoverTimer for the back-off algorithm
     */
    AJ_InitTimer(&stopwatch);
    AJ_InitTimer(&discoverTimer);
    /*
     * Enable multicast I/O for the discovery packets.
     */
    status = AJ_Net_MCastUp(&sock);
    if (status != AJ_OK) {
        AJ_InfoPrintf(("AJ_Discover(): status=%s\n", AJ_StatusText(status)));
        return status;
    }
    while ((int32_t)timeout > 0) {
        if (sendDiscovery(discoverAttempts, &discoverTimer)) {
            discoverAttempts++;
            AJ_IO_BUF_RESET(&sock.tx);
            AJ_InfoPrintf(("AJ_Discover(): WHO-HAS \"%s\"\n", prefix));
            ComposeWhoHas(&sock.tx, prefix);
            status = sock.tx.send(&sock.tx);
            AJ_InfoPrintf(("AJ_Discover(): status=%s\n", AJ_StatusText(status)));
            /*
             * If the send failed the socket has probably gone away.
             */
            if (status != AJ_OK) {
                goto _Exit;
            }
        }
        /*
         * Pause between sending each WHO-HAS
         */
        AJ_InitTimer(&recvStopWatch);
        while (TRUE) {
            AJ_IO_BUF_RESET(&sock.rx);
            status = sock.rx.recv(&sock.rx, AJ_IO_BUF_SPACE(&sock.rx), AJ_WHO_HAS_TIMEOUT);
            if (status != AJ_OK) {
                /*
                 * If we got anything other than timeout we need to bail
                 */
                if (status != AJ_ERR_TIMEOUT) {
                    goto _Exit;
                }
            } else {
                memset(service, 0, sizeof(AJ_Service));
                AJ_InfoPrintf(("AJ_Discover(): ParseIsAt()"));
                status = ParseIsAt(&sock.rx, prefix, service);
                if (status == AJ_OK) {
                    AJ_InfoPrintf(("AJ_Discover(): IS-AT \"%s\"\n", prefix));
                    goto _Exit;
                }
            }
            if (AJ_GetElapsedTime(&recvStopWatch, TRUE) > AJ_WHO_HAS_TIMEOUT) {
                break;
            }
        }

        timeout -= AJ_GetElapsedTime(&stopwatch, FALSE);
    }
_Exit:
    /*
     * All done with multicast for now
     */
    AJ_Net_MCastDown(&sock);

    AJ_InfoPrintf(("AJ_Discover(): Stop discovery of \"%s\"\n", prefix));
    return status;
}
