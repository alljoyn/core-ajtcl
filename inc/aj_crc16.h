#ifndef _AJ_CRC16_H
#define _AJ_CRC16_H

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

#include <ajtcl/aj_target.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Computes a 16-bit CRC on a buffer. The caller provides the context for the running CRC.
 *
 * @param buffer         buffer over which to compute the CRC
 * @param bufLen         length of the buffer in bytes
 * @param runningCrc     On input the current CRC, on output the updated CRC.
 */
void AJ_CRC16_Compute(const uint8_t* buffer,
                      uint16_t bufLen,
                      uint16_t* runningCrc);

/**
 * This function completes the CRC computation by rearranging the CRC bits and bytes
 * into the correct order.
 *
 * @param crc       computed crc as calculated by AJ_CRC16_Compute()
 * @param crcBlock  pointer to a 2-byte buffer where the resulting CRC will be stored
 */

void AJ_CRC16_Complete(uint16_t crc,
                       uint8_t* crcBlock);

#ifdef __cplusplus
}
#endif

#endif /* _AJ_CRC16_H */