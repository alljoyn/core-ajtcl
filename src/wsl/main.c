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

#include <ajtcl/aj_target_platform.h>
#include <ajtcl/aj_target.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_target_rtos.h>

static void main_task(void* parameters)
{
    AJ_PlatformInit();
    AJ_AlwaysPrintf((" ==============================================\n"));
    AJ_AlwaysPrintf(("||       Alljoyn Thin Client + FreeRTOS       ||\n"));
    AJ_AlwaysPrintf((" ==============================================\n"));
    AllJoyn_Start(0);
    while (1);
}

int main(void)
{
    AJ_CreateTask(main_task, (const signed char*)"AlljoynTask", AJ_WSL_STACK_SIZE, NULL, 2, NULL);
    AJ_StartScheduler();
    return 0;
}
