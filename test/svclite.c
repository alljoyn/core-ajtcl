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

#include <aj_target.h>
#include <aj_link_timeout.h>
#include <alljoyn.h>

/*
 * Modify these variables to change the service's behavior
 */

static const char ServiceName[] = "org.alljoyn.svclite";
static const uint16_t ServicePort = 24;
static const uint8_t CancelAdvertiseName = FALSE;
static const uint8_t ReflectSignal = FALSE;

/*
 * An application property to SET or GET
 */
static int32_t propVal = 123456;

/*
 * To define a secure interface, prepend '$' before the interface name, eg., "$org.alljoyn.alljoyn_test"
 */
static const char* const testInterface[] = {
#ifdef SECURE_INTERFACE
    "$org.alljoyn.alljoyn_test",
#else
    "org.alljoyn.alljoyn_test",
#endif
    "?my_ping inStr<s outStr>s",
    "?delayed_ping inStr<s delay<u outStr>s",
    "?time_ping <u <q >u >q",
    "!my_signal >a{ys}",
    NULL
};


static const char* const testValuesInterface[] = {
#ifdef SECURE_INTERFACE
    "$org.alljoyn.alljoyn_test.values",
#else
    "org.alljoyn.alljoyn_test.values",
#endif
    "@int_val=i",
    "@str_val=s",
    "@ro_val>s",
    NULL
};

static const AJ_InterfaceDescription testInterfaces[] = {
    AJ_PropertiesIface,
    testInterface,
    testValuesInterface,
    NULL
};

static const AJ_Object AppObjects[] = {
    { "/org/alljoyn/alljoyn_test", testInterfaces },
    { NULL }
};



/*
 * Message identifiers for the method calls this application implements
 */
#define APP_GET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define APP_SET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define APP_MY_PING         AJ_APP_MESSAGE_ID(0, 1, 0)
#define APP_DELAYED_PING    AJ_APP_MESSAGE_ID(0, 1, 1)
#define APP_TIME_PING       AJ_APP_MESSAGE_ID(0, 1, 2)
#define APP_MY_SIGNAL       AJ_APP_MESSAGE_ID(0, 1, 3)

/*
 * Property identifiers for the properies this application implements
 */
#define APP_INT_VAL_PROP AJ_APP_PROPERTY_ID(0, 2, 0)

/*
 * Let the application do some work
 */
static void AppDoWork(void* context)
{
    /*
     * This function is called if there are no messages to unmarshal
     */
    AJ_Printf("do work\n");
}

static const char PWD[] = "ABCDEFGH";

static uint32_t PasswordCallback(uint8_t* buffer, uint32_t bufLen)
{
    memcpy(buffer, PWD, sizeof(PWD));
    return sizeof(PWD) - 1;
}

/**
 * This is our method handler.  Its reply will be sent by the caller
 */
static AJ_Status AppHandlePing(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Arg arg;

    AJ_UnmarshalArg(msg, &arg);
    /*
     * Just return the arg we received
     */
    return AJ_MarshalArg(reply, &arg);
}

/**
 *  AppHandleMySignal, SessionLost and SessionJoined are incoming signals.
 *  As such, the second parameter (reply) will be NULL and shouldn't be used.
 */
static AJ_Status AppHandleMySignal(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;
    AJ_InfoPrintf(("Received my_signal\n"));

    if (ReflectSignal) {
        AJ_Message out;
        AJ_MarshalSignal(msg->bus, &out, APP_MY_SIGNAL, msg->destination, msg->sessionId, 0, 0);
        AJ_MarshalArgs(&out, "a{ys}", 0, NULL);
        AJ_DeliverMsg(&out);
        AJ_CloseMsg(&out);
    }

    return status;
}

#define CB_TIMEOUT (5 * 1000)

static uint32_t timer_id = 0;

static AJ_Status SessionLost(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;
    AJ_InfoPrintf(("Session Lost\n"));

    if (timer_id) {
        AJ_CancelTimer(timer_id);
        timer_id = 0;
    }

    if (CancelAdvertiseName) {
        status = AJ_BusAdvertiseName(msg->bus, ServiceName, AJ_TRANSPORT_ANY, AJ_BUS_START_ADVERTISING);
    }
    return status;
}

static AJ_Status SessionJoined(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;

    if (CancelAdvertiseName) {
        status = AJ_BusAdvertiseName(msg->bus, ServiceName, AJ_TRANSPORT_ANY, AJ_BUS_START_ADVERTISING);
    }
    return status;
}





static uint8_t AcceptSession(AJ_Message* msg)
{
    uint8_t accepted;
    uint16_t port;
    uint32_t sessionId;
    char* joiner;
    AJ_UnmarshalArgs(msg, "qus", &port, &sessionId, &joiner);

    if (port == ServicePort) {
        accepted = TRUE;
        AJ_InfoPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
    } else {
        accepted = FALSE;
        AJ_InfoPrintf(("Accepted rejected session_id=%u joiner=%s\n", sessionId, joiner));
    }

    return accepted;
}

/*
 * Handles a property GET request so marshals the property value to return
 */
static AJ_Status PropGetHandler(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    if (propId == APP_INT_VAL_PROP) {
        return AJ_MarshalArgs(replyMsg, "i", propVal);
    } else {
        return AJ_ERR_UNEXPECTED;
    }
}

/*
 * Handles a property SET request so unmarshals the property value to apply.
 */
static AJ_Status PropSetHandler(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    if (propId == APP_INT_VAL_PROP) {
        return AJ_UnmarshalArgs(replyMsg, "i", &propVal);
    } else {
        return AJ_ERR_UNEXPECTED;
    }
}



// a table of message handlers
static const MessageHandlerEntry Handlers[] = {
    { APP_MY_PING, &AppHandlePing },
    { APP_MY_SIGNAL, &AppHandleMySignal },
    { AJ_SIGNAL_SESSION_LOST, &SessionLost },
    { AJ_SIGNAL_SESSION_JOINED, &SessionJoined },
    { 0, NULL }
};

// need a list because {Set,Get}Property could appear in multiple bus objects
static const PropHandlerEntry PropHandlers[] = {
    { APP_SET_PROP, PropSetHandler, NULL },
    { APP_GET_PROP, PropGetHandler, NULL },
    { 0, NULL, NULL }
};


uint32_t MyBusAuthPwdCB(uint8_t* buf, uint32_t bufLen)
{
    const char* myPwd = "1234";
    strncpy((char*)buf, myPwd, bufLen);
    return (uint32_t)strlen(myPwd);
}

#define CONNECT_TIMEOUT    (1000 * 1000)
#define UNMARSHAL_TIMEOUT  (1000 * 5)

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;

    AllJoynConfiguration config;
    memset(&config, 0, sizeof(AllJoynConfiguration));
    config.daemonName = NULL;
    config.connect_timeout = CONNECT_TIMEOUT;
    config.connected = FALSE;
    config.session_port = ServicePort;
    config.service_name = ServiceName;
    config.flags = AJ_NAME_REQ_DO_NOT_QUEUE;
    config.opts = NULL;

    config.password_callback = &PasswordCallback;
    config.link_timeout = 60;
    config.message_handlers = Handlers;
    config.prop_handlers = PropHandlers;

    config.acceptor = &AcceptSession;
    config.connection_handler = NULL;


    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);

    SetBusAuthPwdCallback(MyBusAuthPwdCB);

    timer_id = AJ_SetTimer(CB_TIMEOUT, &AppDoWork, NULL, CB_TIMEOUT);
    AJ_InfoPrintf(("Timer Set\n"));

    // magical function that does *everything* !!!
    status = AJ_RunAllJoynService(&bus, &config);
    AJ_WarnPrintf(("svclite EXIT %s\n", AJ_StatusText(status)));
    return status;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif