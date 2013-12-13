#ifndef _AJ_SEMAPHORE_H
#define _AJ_SEMAPHORE_H
/**
 * @file
 */
/******************************************************************************
 *  * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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

#include "aj_target.h"

/**
 * This is the maximum number of simultaneous accessors for a semaphore
 */
#define AJ_SEMAPHORE_VALUE_MAX 0x7fff


/**
 * Create a semaphore.
 *
 * @param name               A string name for the semaphore (optional)
 * @param count              the initial count value
 */
AJ_Semaphore* AJ_SemaphoreCreate(char* name,
                                 int32_t count);

/**
 * Destory a semaphore.
 *
 * @param sem                Identifies a semaphore to destroy
 */
void AJ_SemaphoreDestroy(AJ_Semaphore* sem);

/**
 * wait for a semaphore.
 *
 * @param sem                Identifies a semaphore to wait for
 */
AJ_Status AJ_SemaphoreWait(AJ_Semaphore* sem);

/**
 * wait for a semaphore until a timeout expires
 *
 * @param sem                Identifies a semaphore to wait for
 * @param timeout            Identifies the amount of time to wait for the semaphore
 */
AJ_Status AJ_SemaphoreWaitTimed(AJ_Semaphore* sem,
                                uint32_t timeout);

/**
 * unlock a semaphore.
 *
 * @param sem        Identifies a semaphore to unlock
 */
AJ_Status AJ_SemaphoreUnlock(AJ_Semaphore* sem);


#endif /* _AJ_SEMAPHORE_H */
