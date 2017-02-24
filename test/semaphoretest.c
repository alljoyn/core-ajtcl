/**
 * @file  Semaphore Tester
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
 *    
 *    SPDX-License-Identifier: Apache-2.0
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *    
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *    
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
******************************************************************************/
#include <stdio.h>
#include "aj_target.h"
#include "alljoyn.h"
#include "aj_util.h"
#include "aj_debug.h"
#include "aj_bufio.h"
#include "aj_timer.h"
#include "aj_semaphore.h"

void TimerCallbackUnlockSemaphore(uint32_t timerId, void* context)
{
    AJ_Printf("TimerCallbackUnlockSemaphore %.6d name:%s\n", timerId, ((AJ_Semaphore*)context)->name);
    AJ_SemaphoreUnlock((AJ_Semaphore*)context);
}

int AJ_Main()
{
    AJ_Status status;


/*
 * test output should look like this:
 *
 * AJ_SemaphoreCreate(semA,1)
 * AJ_SemaphoreCreate(semB,0)
 * AJ_SemaphoreCreate(semC,0)
 * Added id 111
 * Added id 222
 * Added id 333
 * AJ_SemaphoreWait semA
 * After wait semA
 * AJ_SemaphoreWait semB
 * TimerCallbackUnlockSemaphore 000111 name:semA
 * AJ_SemaphoreUnlock semA
 * TimerCallbackUnlockSemaphore 000222 name:semB
 * AJ_SemaphoreUnlock semB
 * After wait semB
 * TimerCallbackUnlockSemaphore 000333 name:semC
 * AJ_SemaphoreUnlock semC
 */


    AJ_Semaphore* semA = AJ_SemaphoreCreate("semA", 1);
    AJ_Semaphore* semB = AJ_SemaphoreCreate("semB", 0);
    AJ_Semaphore* semC = AJ_SemaphoreCreate("semC", 0);

    uint32_t timer1 = 111;
    status = AJ_TimerRegister(1000, &TimerCallbackUnlockSemaphore, semA, &timer1);
    AJ_Printf("Added id %u\n", timer1);
    uint32_t timer2 = 222;
    status = AJ_TimerRegister(2000, &TimerCallbackUnlockSemaphore, semB, &timer2);
    AJ_Printf("Added id %u\n", timer2);
    uint32_t timer3 = 333;
    status = AJ_TimerRegister(3000, &TimerCallbackUnlockSemaphore, semC, &timer3);
    AJ_Printf("Added id %u\n", timer3);


    // wait for the semaphore (you should get there right away,
    AJ_SemaphoreWait(semA);
    AJ_Printf("After wait semA\n");

    // wait for the next semaphore, which should be after the second timer fires
    AJ_SemaphoreWait(semB);
    AJ_Printf("After wait semB\n");

    AJ_Sleep(5000);

    AJ_SemaphoreDestroy(semA);
    AJ_SemaphoreDestroy(semB);
    AJ_SemaphoreDestroy(semC);

    return(0);
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif