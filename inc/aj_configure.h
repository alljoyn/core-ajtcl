/**
 * @file aj_configure.h
 * @defgroup aj_configure Wi-Fi Configuration Interface
 * @{
 */
/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
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


#ifndef _AJ_CONFIGURE_H
#define _AJ_CONFIGURE_H

#include <aj_introspect.h>
#include "aj_configureme.h"

/** Note to OEM: Make this the *FIRST* object in your list of AllJoyn objects */
extern const AJ_InterfaceDescription AJ_ConfigInterfaces[];

/**
 *  Attempt to process an internal configuration message
 *
 *  @param msg                  the incoming message
 *  @param identifyFunction     IdentifyFunction
 *
 *  @return
 *          - AJ_OK if we have processed the message
 *          - AJ_ERR_RESTART means that the OEM program should restart its event loop
 *          - AJ_ERR_UNEXPECTED if we dont' know the message; the app should process it!
 **/
AJ_Status AJ_ProcessInternal(AJ_Message* msg, IdentifyFunction identifyFunction);

/**
 * @}
 */
#endif