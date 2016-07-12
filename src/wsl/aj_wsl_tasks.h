/**
 * @file Function declarations for tasks
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
 ******************************************************************************/

#ifndef AJ_WSL_TASKS_H_
#define AJ_WSL_TASKS_H_

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_status.h>

#include "aj_wsl_target.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This file contains the task and structure definitions for the WSL "driver" code
 *
 */

AJ_EXPORT void AJ_WSL_MBoxListenAndProcessTask(void* parameters);

#ifdef __cplusplus
}
#endif

#endif /* AJ_WSL_TASKS_H_ */
