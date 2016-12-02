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

#include "alljoyn.h"
#include "aj_debug.h"

static const char ServiceName[] = "org.alljoyn.ajlite";

#define CONNECT_TIMEOUT    (1000 * 60)
#define UNMARSHAL_TIMEOUT  (1000 * 5)

int AJ_Main()
{
    AJ_Status status;
    AJ_BusAttachment bus;

    AJ_Initialize();

    status = AJ_FindBusAndConnect(&bus, NULL, CONNECT_TIMEOUT);
    if (status == AJ_OK) {
        status = AJ_BusRequestName(&bus, ServiceName, AJ_NAME_REQ_DO_NOT_QUEUE);
    }
    while (status == AJ_OK) {
        AJ_Message msg;
        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_OK) {
            status = AJ_BusHandleBusMessage(&msg);
        }
        AJ_CloseMsg(&msg);
    }

    return 0;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif