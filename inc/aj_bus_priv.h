#ifndef _AJ_BUS_PRIV_H
#define _AJ_BUS_PRIV_H

/**
 * @file aj_bus_priv.h
 * @defgroup aj_bus_priv Non-public Bus Attachment APIs
 * @{
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
 ******************************************************************************/

#include <ajtcl/alljoyn.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Do session bookkeeping when a hosted session is joined
 *
 * @param msg    The AJ_SIGNAL_SESSION_JOINED message
 *
 * @return  - AJ_OK if all went well
 *          - AJ_ERR_SIGNATURE if the message was the signature was missing or incorrect.
 */
AJ_EXPORT
AJ_Status AJ_BusHandleSessionJoined(AJ_Message* msg);

/**
 * Do session bookkeeping when a session is lost
 *
 * @param msg    The AJ_SIGNAL_SESSION_LOST message
 *
 * @return  - AJ_OK if all went well
 *          - AJ_ERR_SIGNATURE if the message was the signature was missing or incorrect.
 */
AJ_EXPORT
AJ_Status AJ_BusHandleSessionLost(AJ_Message* msg);

/**
 * Do session bookkeeping when a session is lost
 *
 * @param msg    The AJ_SIGNAL_SESSION_LOST_WITH_REASON message
 *
 * @return  - AJ_OK if all went well
 *          - AJ_ERR_SIGNATURE if the message was the signature was missing or incorrect.
 */
AJ_EXPORT
AJ_Status AJ_BusHandleSessionLostWithReason(AJ_Message* msg);

/**
 * Do session bookkeeping when a JoinSession reply comes in
 *
 * @param msg    The AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION) message
 *
 * @return  - AJ_OK if all went well
 *          - AJ_ERR_SIGNATURE if the message was the signature was missing or incorrect.
 */
AJ_EXPORT
AJ_Status AJ_BusHandleJoinSessionReply(AJ_Message* msg);

/**
 * Look up an ongoing session by session id.
 *
 * @param bus        The AJ_BusAttachment
 * @param sessionId  The session id of the session to look up
 *
 * @return  pointer to the AJ_Session or NULL if not found
 */
AJ_EXPORT
AJ_Session* AJ_BusGetOngoingSession(AJ_BusAttachment* bus, uint32_t sessionId);

/**
 * Clean up the sessions list in the bus attachment - to be called during AJ_BusAttachment cleanup
 *
 * @param bus    The AJ_BusAttachment
 */
AJ_EXPORT
void AJ_BusRemoveAllSessions(AJ_BusAttachment* bus);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif
