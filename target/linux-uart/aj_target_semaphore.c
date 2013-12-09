/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2013, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include "aj_target.h"
#include "aj_status.h"
#include "aj_timer.h"
#include "aj_util.h"
#include "aj_semaphore.h"
#include <semaphore.h>
#include <errno.h>

const uint32_t AJ_SEMAPHORE_TAKEN = 1;

AJ_Semaphore* AJ_SemaphoreCreate(char* name,
                                 int32_t count)
{
    if (name) {
        AJ_Printf("AJ_SemaphoreCreate(%s,%d)\n", name, count);
    }

    AJ_Semaphore* ret = (AJ_Semaphore*) AJ_Malloc(sizeof(AJ_Semaphore));
    if (ret) {
        sem_init(&ret->sem, 0, count);
        ret->name = (char*) AJ_Malloc(strlen(name) + 1);
        strcpy(ret->name, name);
    }
    return ret;
}

void AJ_SemaphoreDestroy(AJ_Semaphore* sem)
{
    if (sem && sem->name) {
        AJ_Printf("AJ_SemaphoreDestroy(%s)\n", sem->name);
    }

    AJ_Free(sem->name);
    sem_destroy(&sem->sem);
    AJ_Free(sem);
}


AJ_Status AJ_SemaphoreWait(AJ_Semaphore* sem)
{
    if (sem && sem->name) {
        AJ_Printf("AJ_SemaphoreWait %s\n", sem->name);
    }

    int s;
    while ((s = sem_wait(&sem->sem)) == -1 && errno == EINTR) {
        continue; // the wait was interrupted, probably by the timer, so wait again.
    }

    return AJ_OK;
}


AJ_Status AJ_SemaphoreWaitTimed(AJ_Semaphore* sem,
                                uint32_t timeout)
{
    if (sem && sem->name) {
        AJ_Printf("AJ_SemaphoreWaitTimed %s\n", sem->name);
    }
    assert(0);
    return AJ_ERR_UNEXPECTED;
}


AJ_Status AJ_SemaphoreUnlock(AJ_Semaphore* sem)
{
    if (sem && sem->name) {
        AJ_Printf("AJ_SemaphoreUnlock %s\n", sem->name);
    }

    sem_post(&sem->sem);
    return AJ_OK;
}


