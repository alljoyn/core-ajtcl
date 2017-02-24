/**
 * @file
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

#include "aj_target.h"
#include "aj_status.h"
#include "aj_timer.h"
#include "aj_util.h"
#include <signal.h>
#include <time.h>



static AJ_Time globalClock;
static AJ_Timer* TimerList = NULL;
static AJ_Timer* InactiveTimerList = NULL;
static uint32_t TimerId = 0;
static timer_t globalTimer;
static struct sigevent sigev;

void _AJ_DebugCheckTimerList(AJ_Timer* list)
{
    // BUGBUG take a lock
    AJ_Timer* iter = list;

    while (iter) {
        assert(iter != iter->next);  //check for a single loop
        iter = iter->next;
    }
}


void _AJ_DumpTimerList(AJ_Timer* list)
{
    // BUGBUG take a lock
    AJ_Timer* iter = list;

    while (iter) {
        AJ_Printf("AJ_DumpTimerList id:%u NextRaised sec %u msec %u \n",
                  iter->id,
                  iter->timeNextRaised.seconds,
                  iter->timeNextRaised.milliseconds);

        assert(iter != iter->next);
        iter = iter->next;
    }
    // BUGBUG release a lock
}

#ifdef  AJ_DEBUG_TIMER_LISTS
#define AJ_DumpTimerList(a) _AJ_DumpTimerList(a)
#define AJ_DebugTimerPrintf AJ_Printf
#define AJ_DebugCheckTimerList(a) _AJ_DebugCheckTimerList(a)
#else
#define AJ_DumpTimerList(a)
#define AJ_DebugTimerPrintf(format, args ...) ((void)0)
#define AJ_DebugCheckTimerList(a)
#endif


static void AJ_GlobalTimerStop()
{
    struct itimerspec ts;
    // FYI: setting to zero will turn off the alarm
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    timer_settime(globalTimer, TIMER_ABSTIME, &ts, NULL);
}

static void AJ_GlobalTimerStart()
{
    AJ_DumpTimerList(TimerList);
    AJ_DumpTimerList(InactiveTimerList);

    struct itimerspec ts;
    // FYI: setting to zero will turn off the alarm
    ts.it_value.tv_sec = TimerList->timeNextRaised.seconds;
    ts.it_value.tv_nsec = TimerList->timeNextRaised.milliseconds * 1000000LL;
    ts.it_interval.tv_sec = 0;
//    ts.it_interval.tv_nsec = 0;
    ts.it_interval.tv_nsec = 1000000; // 1 millisecond resolution

    //int settime =
    timer_settime(globalTimer, TIMER_ABSTIME, &ts, NULL);
    AJ_DebugTimerPrintf("timer_settime next time raised will be %u\n", ts.it_value.tv_sec);
}

static void AJ_GlobalTimerHandler(sigval_t value)
{
    if (!TimerList) {
        AJ_GlobalTimerStop();
        AJ_Printf("turn off alarm, there is no timer\n");
    } else {
        AJ_Time now;
        AJ_InitTimer(&now);

        AJ_Timer* top = TimerList;
        // if tops time < now, then run the callback...

        if (AJ_CompareTime(top->timeNextRaised, now) < 1) {
            TimerList = top->next;
            // move to the top of the inactive timer list, semi-MRU
            top->next = InactiveTimerList;
            InactiveTimerList = top;
            (top->callback)(top->id, top->context);
        } else {
//            AJ_Printf("AJ_GlobalTimerHandler without something to do yet.\n");
        }
    }

}

static void AJ_GlobalTimerInit(void)
{
    sigev.sigev_notify = SIGEV_THREAD;
    sigev.sigev_notify_function = &AJ_GlobalTimerHandler;

//    int create;
    timer_create(CLOCK_MONOTONIC, &sigev, &globalTimer);
//    AJ_DebugTimerPrintf("global timer create returned %d id is 0x%lX\n", create, (long)globalTimer);

    AJ_InitTimer(&globalClock);
}


AJ_Timer* AJ_TimerInit(uint32_t timeout,
                       AJ_TimerCallback timerCallback,
                       void* context,
                       uint32_t timerId)
{
    AJ_Timer* timer;
    timer = (AJ_Timer*) AJ_Malloc(sizeof(AJ_Timer));
    timer->id = timerId;
    timer->next = NULL;
    timer->callback = timerCallback;
    timer->context = context;
    AJ_InitTimer(&(timer->timeNextRaised));
    AJ_TimeAddOffset(&(timer->timeNextRaised), timeout);
    return timer;
}



void AJ_TimerInsertInList(AJ_Timer** list, AJ_Timer* newNode)
{
    if (!*list) {
        *list = newNode;
        newNode->next = NULL;
    } else {
        // walk the sorted list, and insert the timer based on when it should be raised next.
        uint8_t inserted = FALSE;
        AJ_Timer* curr = *list;
        AJ_Timer* iter = (*list)->next;
        if (AJ_CompareTime(newNode->timeNextRaised, curr->timeNextRaised) < 0) {
            newNode->next = curr;
            *list = newNode;
            inserted = TRUE;
        } else {
            while (iter) {
                if (AJ_CompareTime(newNode->timeNextRaised, iter->timeNextRaised) < 0) {
                    newNode->next = iter;
                    curr->next = newNode;
                    inserted = TRUE;
                    break;
                }
                curr = iter;
                iter = iter->next;
            }
            // check if we inserted anything.
            if (inserted == FALSE) {
                curr->next = newNode;
            }
        }
    }
    AJ_DebugCheckTimerList(*list);
}

AJ_Timer* AJ_TimerRemoveFromList(AJ_Timer** list, uint32_t timerId)
{
    if (list && *list) {
        // walk the list of timers looking for the matching timerId
        AJ_Timer* curr = *list;
        AJ_Timer* prev = NULL;
        while (curr) {
            if (timerId == curr->id) {
                // check if the previous node was empty, base case
                if (!prev) {
                    *list = curr->next;
                    curr->next = NULL;
                    AJ_DebugCheckTimerList(*list);
                    return curr;
                } else {
                    // remove timer from the list and delete the node
                    prev->next = curr->next;
                    curr->next = NULL;  // detach it from the list
                    AJ_DebugCheckTimerList(*list);
                    return curr;
                }
            }
            // move to the next node.
            prev = curr;
            curr = curr->next;
        }
    } else {
        // deleting a non-extistent timer
        ;
    }
    return NULL;
}


AJ_Status AJ_TimerRegister(uint32_t timeout,
                           AJ_TimerCallback timerCallback,
                           void* context,
                           uint32_t* timerId)
{

    if (TimerId == 0) {
        // no timer has been initialized, perform the global initialization routines.
        AJ_GlobalTimerInit();
        TimerId++;
    }

    AJ_Timer* timer = AJ_TimerInit(timeout, timerCallback, context, *timerId);
    AJ_TimerInsertInList(&TimerList, timer);


    if (TimerList) {
        // Now set the global timer to the next expected event at the head of the list.
        AJ_GlobalTimerStart();
    }
    return AJ_OK;
}

AJ_Status AJ_TimerRefresh(uint32_t timerId,
                          uint32_t timeout)
{
    AJ_DebugTimerPrintf("AJ_TimerRefresh id 0x%lx timeout %ld\n", timerId, timeout);
    // BUGBUG take a lock
    AJ_Timer* iter = NULL;

    iter = AJ_TimerRemoveFromList(&TimerList, timerId);

    if (!iter) {
        iter = AJ_TimerRemoveFromList(&InactiveTimerList, timerId);
    }

    if (iter) {
        // set the trigger time to now + timeout.
        AJ_InitTimer(&(iter->timeNextRaised));
        AJ_TimeAddOffset(&(iter->timeNextRaised), timeout);

        // move a timer from the active to the inactive list.
        AJ_TimerInsertInList(&TimerList, iter);
    }

    if (!iter) {
        // look on the inactive list and insert it into the active list
        AJ_Printf("ERROR! refreshing a non existant timer %u!\n", timerId);
    }

    if (TimerList) {
        // restart the global timer, in case we were stopped.
        AJ_GlobalTimerStart();
    }

    // BUGBUG release a lock
    AJ_DebugCheckTimerList(TimerList);

    return AJ_OK;
}


void AJ_TimerCancel(uint32_t timerId, uint8_t keep)
{
    AJ_DebugTimerPrintf("AJ_TimerCancel id %d\n", timerId);
    // BUGBUG take a lock

    // move a timer from the active to the inactive list.
    AJ_Timer* timer = AJ_TimerRemoveFromList(&TimerList, timerId);

    if (timer && keep) {
        AJ_TimerInsertInList(&InactiveTimerList, timer);
    }

    if (TimerList) {
        // Now set the global timer to the next expected event at the head of the list.
        AJ_GlobalTimerStart();
    }
    // BUGBUG release a lock
}
