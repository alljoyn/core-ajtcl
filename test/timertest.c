/**
 * @file  Timer/Alarm Tester
 */
/******************************************************************************
 * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
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
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#include <stdio.h>
#include "alljoyn.h"
#include "aj_util.h"
#include "aj_debug.h"
#include "aj_bufio.h"
#include "aj_timer.h"

char* past = "past";
char* present = "present";
char* future = "future";

#define MAXTIMERS 40
uint32_t timerIds[MAXTIMERS] = { };
uint32_t timerContexts[MAXTIMERS] = { };
uint32_t raisedOrder[MAXTIMERS] = { };
uint32_t raisedCounter = 0;

void TimerCallbackString(uint32_t timerId, void* context)
{
    AJ_Printf("TimerCallbackString %06d  context %s\n", timerId, (char*)context);
}

void TimerCallbackUInt32(uint32_t timerId, void* context)
{
    raisedOrder[raisedCounter++] = *(uint32_t*)context;
    AJ_Printf("TimerCallback %.6d  context %.8u\n", timerId, *(uint32_t*)context);
}

#ifdef AJ_MAIN
int main()
{
    AJ_Status status;


    AJ_Time now;
    AJ_InitTimer(&now);
    AJ_Time nowcopy;
    memcpy(&nowcopy, &now, sizeof(nowcopy));

    if (AJ_CompareTime(now, nowcopy) == 0) {
        AJ_Printf("now == nowcopy\n");
    } else {
        AJ_Printf("ERROR now != copy\n");
    }

    AJ_Sleep(100);

    AJ_Time later;
    AJ_InitTimer(&later);

    AJ_Printf("now was  s:%u ms:%u\n", now.seconds, now.milliseconds);
    AJ_Printf("later is s:%u ms:%u\n", later.seconds, later.milliseconds);


    if (AJ_CompareTime(now, later) < 0) {
        AJ_Printf("now < later\n");
    }

    int32_t elapsed = AJ_GetTimeDifference(&later, &now);
    AJ_Printf("elapsed %d\n", elapsed);


    AJ_TimeAddOffset(&now, 100);
    AJ_Printf("now is now s:%u ms:%u\n", now.seconds, now.milliseconds);


    AJ_TimeAddOffset(&now, -1);
    AJ_Printf("now is now s:%u ms:%u\n", now.seconds, now.milliseconds);


    uint32_t timer1;
    status = AJ_TimerRegister(303, &TimerCallbackString, future, &timer1);
    AJ_Printf("Added id %u\n", timer1);
    uint32_t timer2;
    status = AJ_TimerRegister(202, &TimerCallbackString, present, &timer2);
    AJ_Printf("Added id %u\n", timer2);
    uint32_t timer3;
    status = AJ_TimerRegister(101, &TimerCallbackString, past, &timer3);
    AJ_Printf("Added id %u\n", timer3);


    AJ_Sleep(1000);


    extern AJ_Timer* AJ_TimerRemoveFromList(AJ_Timer** list, uint32_t timerId);
    extern AJ_Status AJ_TimerInsertInList(AJ_Timer** list, AJ_Timer* newNode);
    {
        AJ_Timer* StoreList = NULL;
        AJ_Timer* TempStoreList = NULL;

        uint32_t timerA = 0x1000;
        AJ_Timer* ajtA = NULL;
        AJ_Timer* ajtB = NULL;
        AJ_Timer* ajtC = NULL;
        ajtA = AJ_TimerInit(100000, &TimerCallbackString, "timerA", timerA);
        AJ_Printf("Added id %u\n", timerA);
        uint32_t timerB = 0x2000;
        ajtB = AJ_TimerInit(200000, &TimerCallbackString, "timerB", timerB);
        AJ_Printf("Added id %u\n", timerB);
        uint32_t timerC = 0x3000;
        ajtC = AJ_TimerInit(300000, &TimerCallbackString, "timerC", timerC);
        AJ_Printf("Added id %u\n", timerC);

        AJ_TimerInsertInList(&StoreList, ajtA);
        AJ_TimerInsertInList(&StoreList, ajtB);
        AJ_TimerInsertInList(&StoreList, ajtC);
        AJ_Printf("-------------\ndumped store list\n");
        _AJ_DumpTimerList(StoreList);

        AJ_Printf("-------------\nmove everything from one list to another\n");

        AJ_TimerInsertInList(&TempStoreList, AJ_TimerRemoveFromList(&StoreList, timerA));
        AJ_TimerInsertInList(&TempStoreList, AJ_TimerRemoveFromList(&StoreList, timerB));
        AJ_TimerInsertInList(&TempStoreList, AJ_TimerRemoveFromList(&StoreList, timerC));

        AJ_Printf("-------------\ndumped store list\n");
        _AJ_DumpTimerList(StoreList);
        AJ_Printf("-------------\ndumped TEMP store list\n");
        _AJ_DumpTimerList(TempStoreList);


        AJ_Printf("-------------\nmove everything back to another\n");

        AJ_TimerInsertInList(&StoreList, AJ_TimerRemoveFromList(&TempStoreList, timerA));
        AJ_TimerInsertInList(&StoreList, AJ_TimerRemoveFromList(&TempStoreList, timerB));
        AJ_TimerInsertInList(&StoreList, AJ_TimerRemoveFromList(&TempStoreList, timerC));

        AJ_Printf("-------------\ndumped store list\n");
        _AJ_DumpTimerList(StoreList);


    }


//Single insert remove.
    {
        AJ_Timer* StoreList = NULL;
        AJ_Timer* TempStoreList = NULL;

        uint32_t timerA2 = 0x1000;
        AJ_Timer* ajtA2 = NULL;
        ajtA2 = AJ_TimerInit(100002, &TimerCallbackString, "timerA2", timerA2);
        AJ_Printf("Added id %u\n", timerA2);

        AJ_TimerInsertInList(&StoreList, ajtA2);

        uint32_t timerA3 = 0x2000;
        AJ_Timer* ajtA3 = NULL;
        ajtA3 = AJ_TimerInit(100003, &TimerCallbackString, "timerA3", timerA3);
        AJ_Printf("Added id %u\n", timerA3);

        AJ_TimerInsertInList(&StoreList, ajtA3);

        uint32_t timerA4 = 0x3000;
        AJ_Timer* ajtA4 = NULL;
        ajtA4 = AJ_TimerInit(100004, &TimerCallbackString, "timerA4", timerA4);
        AJ_Printf("Added id %u\n", timerA4);

        AJ_TimerInsertInList(&StoreList, ajtA4);

        AJ_Printf("-------------\ndumped store list\n");
        _AJ_DumpTimerList(StoreList);

        AJ_Printf("-------------\nmove everything from one list to another\n");

        AJ_TimerInsertInList(&TempStoreList, AJ_TimerRemoveFromList(&StoreList, timerA3));
        AJ_TimerInsertInList(&TempStoreList, AJ_TimerRemoveFromList(&StoreList, timerA2));
        AJ_Printf("-------------\ndumped store list\n");
        _AJ_DumpTimerList(StoreList);
        AJ_Printf("-------------\ndumped TEMP store list\n");
        _AJ_DumpTimerList(TempStoreList);


        AJ_Printf("-------------\nmove everything back to another\n");

        AJ_TimerInsertInList(&StoreList, AJ_TimerRemoveFromList(&TempStoreList, timerA3));
        AJ_TimerInsertInList(&StoreList, AJ_TimerRemoveFromList(&TempStoreList, timerA2));

        AJ_Printf("-------------\ndumped store list\n");
        _AJ_DumpTimerList(StoreList);
        AJ_Printf("-------------\ndumped TEMP store list\n");
        _AJ_DumpTimerList(TempStoreList);


    }




    // add a number of timer objects, with increasing trigger times
    uint32_t i;
    for (i = 0; i < ArraySize(timerIds); i++) {
        timerContexts[i] = i;
        status = AJ_TimerRegister(1000 + (100 * i), &TimerCallbackUInt32, &timerContexts[i], &timerIds[i]);
    }


    AJ_Sleep(10000);

    for (i = 0; i < ArraySize(raisedOrder); i++) {
        AJ_Printf("raised %06u\n", raisedOrder[i]);
        //TODO: check that the timers were raised in the right order
    }



    return(0);
}
#endif