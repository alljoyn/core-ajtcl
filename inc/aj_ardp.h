/**
 * @file ArdpProtocol is an implementation of the Reliable Datagram Protocol
 * (RDP) adapted to AllJoyn.
 */

/******************************************************************************
 * Copyright (c) 2015, AllSeen Alliance. All rights reserved.
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

#ifndef _ALLJOYN_ARDP_PROTOCOL_H
#define _ALLJOYN_ARDP_PROTOCOL_H

#ifdef AJ_ARDP

#ifdef __cplusplus
extern "C" {
#endif

#include "aj_target.h"
#include "aj_status.h"
#include "aj_bufio.h"

/**
 * @brief Per-protocol-instance (global) configuration variables.
 */
#define UDP_CONNECT_TIMEOUT 1000  /**< How long before we expect a connection to complete */
#define UDP_CONNECT_RETRIES 10  /**< How many times do we retry a connection before giving up */
#define UDP_INITIAL_DATA_TIMEOUT 1000  /**< Initial value for how long do we wait before retrying sending data */
#define UDP_TOTAL_DATA_RETRY_TIMEOUT 30000  /**< Initial total amount of time to try and send data before giving up */
#define UDP_MIN_DATA_RETRIES 5  /**< Minimum number of times to try and send data before giving up */
#define UDP_PERSIST_INTERVAL 1000  /**< How long do we wait before pinging the other side due to a zero window */
#define UDP_TOTAL_APP_TIMEOUT 30000  /**< How long to we try to ping for window opening before deciding app is not pulling data */
#define UDP_LINK_TIMEOUT 30000  /**< How long before we decide a link is down (with no reponses to keepalive probes */
#define UDP_KEEPALIVE_RETRIES 5  /**< How many times do we try to probe on an idle link before terminating the connection */
#define UDP_FAST_RETRANSMIT_ACK_COUNTER 1  /**< How many duplicate acknowledgements to we need to trigger a data retransmission */
#define UDP_DELAYED_ACK_TIMEOUT 100 /**< How long do we wait until acknowledging received segments */
#define UDP_TIMEWAIT 1000  /**< How long do we stay in TIMWAIT state before releasing the per-connection resources */
#define UDP_MINIMUM_TIMEOUT 100 /**< The minimum amount of time between calls to ARDP_Recv */
#define UDP_BACKPRESSURE_TIMEOUT 100 /**< How long can backpressure block the program before a disconnect is triggered? */

#define UDP_SEGBMAX 1472  /**< Maximum size of an ARDP segment (quantum of reliable transmission) */
#define UDP_SEGMAX 4  /**< Maximum number of ARDP segment in-flight (bandwidth-delay product sizing) */


/* Protocol specific values */
#define UDP_HEADER_SIZE 8
#define ARDP_HEADER_SIZE 36
#define ARDP_TTL_INFINITE   0

/*
 * SEGMAX and SEGBMAX  on both send and receive sides are inidcted by SYN header in Connection request:
 * the acceptor cannot modify these parameters, only reject in case the request cannot be accomodated.
 * No EACKs: only acknowledge segments received in sequence.
 */
#define ARDP_FLAG_SIMPLE_MODE 2

/*
 *       ARDP onnection request. Connect begins the SYN,
 *       SYN-ACK, ACK thre-way handshake.
 *
 *       Returns error code:
 *         AJ_OK - all is good, connection transitioned to SYN_SENT state;
 *         fail error code otherwise
 */
AJ_Status ARDP_Connect(uint8_t* data, uint16_t dataLen, void* context);

/*
 *      Disconnect is used to actively close the connection.
 *          forced (IN) - if set to TRUE, the connection should be torn down regardless
 *                        of whether there are pending data retransmits. Otherwise, the
 *                        callee should check the value of returned error code.
 *       Returns error code:
 *          AJ_OK - connection is gone
 *          AJ_ERR_ARDP_DISONNECTING - not all outboud data was ACKed yet. Call ARDP_Recv()
 *                  when  there are data to read from the socket and wait for either
 *                  AJ_ERR_ARDP_DISCONNECTED or AJ_ERR_ARDP_REMOTE_CONNECTION_RESET to be retruned.
 */
AJ_Status ARDP_Disconnect(uint8_t forced);

/*
 *      StartMsgSend informs the ARDP protocol that next chunk of data to be sent
 *      is a beginning of anew message with a specified TTL.
 *      Returns error code:
 *         AJ_OK - all is good
 *         AJ_ERR_ARDP_TTL_EXPIRED - Discard this message. TTL is less than 1/2 estimated roundtrip time.
 *         AJ_ERR_ARDP_INVALID_CONNECTION - Connection does not exist (efffectively connection record is NULL)
 */
AJ_Status ARDP_StartMsgSend(uint32_t ttl);

/*
 *       Send is a synchronous send. The data being sent is buffered at the protocol
 *       level.
 *       Returns error code:
 *         AJ_OK - all is good
 *         AJ_ERR_ARDP_TTL_EXPIRED - Discard the message that is currently being marshalled.
 *         AJ_ERR_ARDP_BACKPRESSURE - Send window does not allow immediate transmission.
 *         AJ_ERR_DISALLOWED - Connection does not exist (efffectively connection record is NULL)
 *
 */
AJ_Status ARDP_Send(uint8_t* txBuf, uint16_t len);

/*
 *       Recv is a main state machine where the data is being read, buffered
 *       timers are checked.
 *         rxBuf - 9IN) buffer from where to read incoming (socket) data.
 *         len   - (IN) socket buffer size
 *         dataBuf - (OUT) pointer to received data payload.
 *         dataLen - (OUT) length of data payload. Zero, if no data has been received.
 *         context - (OUT) pointer to ARDP Recv context (to be retruned with ARDP_RecvReady() call)
 *       Returns error code:
 *         AJ_OK - all is good
 *         AJ_ERR_ARDP_TTL_EXPIRED - Discard the message that is currently being unMarshalled.
 *                                   If dataLen is not zero, the payload is associated with new
 *                                   message and the old one needs to be discarded.
 *         Note: If the returned status is anything but AJ_OK or AJ_ERR_ARDP_TTL_EXPIRED,
 *               the connection does not exist anymore and all the associated resources are freed.
 *               No further ARDP action is expected/required. Possible error codes:
 *         AJ_ERR_DISALLOWED - Connection does not exist (efffectively connection record is NULL)
 *         AJ_ERR_ARDP_DISCONNECTED - ARDP layer issued disconnect based either on outstanding ARDP_Disconnect()
 *                request or due to invalid response or corrupted data.
 *         AJ_ERR_ARDP_REMOTE_CONNECTION_RESET - Remote requested disconnect.
 *
 */
AJ_Status ARDP_Recv(uint8_t* rxBuf, uint16_t len, uint8_t** dataBuf, uint16_t* dataLen, void** context);


struct _AJ_IOBuffer;
struct _AJ_NetSocket;

/**
 * AJ_ARDP_Send will attempt to send the data in buf.  It will attempt to send the message, waiting for
 *      backpressure to clear if necessary.  It can potentially block for as long as is necessary
 *      for the backpressure to be cleared.
 *
 * returns:
 *      AJ_OK - if we sent successfully
 *      AJ_ERR_WRITE - if we were unable to send.
 */
AJ_Status AJ_ARDP_Send(struct _AJ_IOBuffer* buf);

AJ_Status AJ_ARDP_Recv(struct _AJ_IOBuffer* rxBuf, uint32_t len, uint32_t timeout);

/**
 * Set hte NetSocket for the current connection
 */
void AJ_ARDP_SetNetSock(struct _AJ_NetSocket* net_sock);

/*
 *       RecvReady informs ARDP layer that the received data buffer that was passed
 *       in ARDP_Recv() has been consumed.
 *         context - (IN) pointer to ARDP Recv context (should correspond the one in ARDP_Recv() call).
 */
void ARDP_RecvReady(void* context);

#ifdef __cplusplus
}
#endif

#endif // AJ_ARDP

#endif // _ALLJOYN_ARDP_PROTOCOL_H
