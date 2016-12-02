/**
 * @file   RTOS specific header file
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

/******************************************************************************
 * Any time in this file there is a comment including FreeRTOS or calling a
 * FreeRTOS API, note that the API associated with it may be subject to the
 * FreeRTOS GPL with exception license copied here:
 * http://www.freertos.org/license.txt :

 * The FreeRTOS.org source code is licensed by the modified GNU General Public
 * License (GPL) text provided below.  The FreeRTOS download also includes
 * demo application source code, some of which is provided by third parties
 * AND IS LICENSED SEPARATELY FROM FREERTOS.ORG.
 * For the avoidance of any doubt refer to the comment included at the top
 * of each source and header file for license and copyright information.
 ******************************************************************************/

#ifndef AJ_TARGET_RTOS_H_
#define AJ_TARGET_RTOS_H_

#include <FreeRTOS.h>
#include <task.h>
#include <queue.h>
#include <timers.h>
#include <semphr.h>

#include "aj_rtos.h"

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
 * This function is called when freeRTOS fails to allocate
 */
void vApplicationMallocFailedHook(void);

/**
 * This function is called when a tasks stack overflows
 *
 * @param pxTask        Task handle of the task thats stack overflowed
 * @param pcTaskName    Name of the task
 */
void vApplicationStackOverflowHook(xTaskHandle pxTask, signed char*pcTaskName);

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

/**
 * Resume a task that has been previously started
 *
 * @param handle        The task handle (returned from AJ_CreateTask())
 * @param inISR         If the calling function is in an interrupt routine
 *
 * @return              AJ_OK if the task was resumed sucessfully
 */
AJ_Status AJ_ResumeTask(struct AJ_TaskHandle* handle, uint8_t inISR);

#ifdef __cplusplus
}
#endif

#endif /* AJ_TARGET_RTOS_H_ */