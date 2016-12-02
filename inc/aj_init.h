#ifndef _AJ_INIT_H
#define _AJ_INIT_H

/**
 * @file aj_init.h
 * @defgroup aj_init Initialization
 * @{
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
 * Initialization for AllJoyn. This function should be called before calling any
 * other AllJoyn APIs.
 */
AJ_EXPORT void AJ_Initialize(void);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif