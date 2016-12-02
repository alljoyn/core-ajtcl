/******************************************************************************
 *
 *
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/

#include <gtest/gtest.h>

extern "C" {
#include "aj_debug.h"
#include "alljoyn.h"
}

class DiscoveryTest : public testing::Test {
  public:

    virtual void SetUp() {
        AJ_Initialize();

    }
    virtual void TearDown() {
    }
};

TEST_F(DiscoveryTest, DiscoverValidBusNodeName)
{
    // Attempt to discover a valid bus node name that is being advertised.
    AJ_Service service;
    AJ_Service newService = { 0, 0, 0, 0, 0x0100007f, 1234, 0, { 0, 0, 0, 0 } };
    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&newService);
    AJ_Status status = AJ_Discover("org.alljoyn.BusNode", &service, 5000, 5000);
    AJ_InitRoutingNodeResponselist();
    EXPECT_EQ(AJ_OK, status) << "Unable to discover routing node. Got status " << AJ_StatusText(status);

}

TEST_F(DiscoveryTest, DiscoverInValidBusNodeName)
{
    // Attempt to discover an invalid bus node name that is not being advertised.
    AJ_Service service;
    AJ_InitRoutingNodeResponselist();
    AJ_Status status = AJ_Discover("org.alljoyn.BusNodezzzz", &service, 5000, 5000);
    EXPECT_EQ(AJ_ERR_TIMEOUT, status) << "Able to discover invalid routing node. Got status " << AJ_StatusText(status);
}

TEST_F(DiscoveryTest, SelectPriority)
{
    // Select between two routing nodes with different priorities.
    AJ_Service service;
    AJ_Service serviceHighScore = { 0, 0, 0, 0, 0x0100007f, 1234, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowScore =  { 0, 0, 0, 0, 0x0200007f, 5678, 0, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceHighScore);
    AJ_AddRoutingNodeToResponseList(&serviceLowScore);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceHighScore.priority, service.priority) << "Wrong priority selected from the response list";
    EXPECT_EQ(serviceHighScore.ipv4, service.ipv4) << "Wrong ipv4 address selected from the response list";
}

TEST_F(DiscoveryTest, SelectProtocolVersion)
{
    // Select between two routing nodes with different protocol versions.
    AJ_Service service;
    AJ_Service serviceOldProtocol = { 0, 0, 0, 0, 0x0100007f, 0, 11, { 0, 0, 0, 0 } };
    AJ_Service serviceNewProtocol =  { 0, 0, 0, 0, 0x0200007f, 5678, 12, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceOldProtocol);
    AJ_AddRoutingNodeToResponseList(&serviceNewProtocol);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceNewProtocol.priority, service.priority) << "Wrong priority selected from the response list";
    EXPECT_EQ(serviceNewProtocol.ipv4, service.ipv4) << "Wrong priority selected from the response list";
}

TEST_F(DiscoveryTest, ExhaustSelection)
{
    // Select from the response list until there are no more responses available.
    AJ_Service service;
    AJ_Service serviceHighScore = { 0, 0, 0, 0, 0x0100007f, 1234, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowScore =  { 0, 0, 0, 0, 0x0200007f, 5678, 0, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceHighScore);
    AJ_AddRoutingNodeToResponseList(&serviceLowScore);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    status = AJ_SelectRoutingNodeFromResponseList(&service);
    status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_ERR_END_OF_DATA, status) << "Response list was not exhausted after all nodes were selected";
}