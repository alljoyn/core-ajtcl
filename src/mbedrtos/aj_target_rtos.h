/**
 * @file   RTOS specific header file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
 ******************************************************************************/

#ifndef AJ_TARGET_RTOS_H_
#define AJ_TARGET_RTOS_H_

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_status.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _AJ_FW_Version {
    uint32_t host_ver;
    uint32_t target_ver;
    uint32_t wlan_ver;
    uint32_t abi_ver;
} AJ_FW_Version;

/**
 * Enter a critical region of code. This function will disable all interrupts
 * until AJ_LeaveCriticalRegion() is called
 */
void AJ_EnterCriticalRegion(void);

/**
 * Leave a critical region of code. This function re-enables interrupts after
 * calling AJ_EnterCriticalRegion()
 */
void AJ_LeaveCriticalRegion(void);

/**
 * Generate an ephemeral (random) port.
 *
 * @return              A random port number
 */
uint16_t AJ_EphemeralPort(void);

/**
 * Initialize the platform. This function contains initialization such
 * as GPIO, Clock, UART etc.
 */
void AJ_PlatformInit(void);

#ifdef __cplusplus
}
#endif

#endif /* AJ_TARGET_RTOS_H_ */
