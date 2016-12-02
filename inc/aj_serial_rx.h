#ifndef _AJ_SERIAL_RX_H
#define _AJ_SERIAL_RX_H

/**
 * @file
 */
/******************************************************************************
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/
#ifdef AJ_SERIAL_CONNECTION

#include "aj_target.h"
#include "aj_status.h"
#include "aj_serial.h"

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