/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 * SDPX-License-Identifier: ISC
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

