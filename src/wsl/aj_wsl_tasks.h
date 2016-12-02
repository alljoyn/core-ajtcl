/**
 * @file Function declarations for tasks
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