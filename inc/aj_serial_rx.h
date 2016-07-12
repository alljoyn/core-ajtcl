#ifndef _AJ_SERIAL_RX_H
#define _AJ_SERIAL_RX_H

/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SPDX-License-Identifier: ISC
 ******************************************************************************/
#ifdef AJ_SERIAL_CONNECTION

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_status.h>
#include <ajtcl/aj_serial.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function initializes the receive path
 */
AJ_Status AJ_SerialRX_Init(void);

/**
 * This function shuts down the receive path
 */
void AJ_SerialRX_Shutdown(void);

/**
 * This function resets the receive path
 */
AJ_Status AJ_SerialRX_Reset(void);

/**
 * Process the buffers read by the Receive callback - called by the StateMachine.
 */
void AJ_ProcessRxBufferList();

#ifdef __cplusplus
}
#endif

#endif /* AJ_SERIAL_CONNECTION */

#endif /* _AJ_SERIAL_RX_H */
