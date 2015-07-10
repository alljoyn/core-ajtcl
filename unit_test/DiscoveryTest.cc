/******************************************************************************
 *
 *
 * Copyright AllSeen Alliance. All rights reserved.
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

#include <gtest/gtest.h>

extern "C" {
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>
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

TEST_F(DiscoveryTest, UpdatePriority)
{
    // Select between two routing nodes with different priorities.
    AJ_Service service;
    AJ_Service serviceHighScore = { 0, 0, 0, 0, 0x0100007f, 1234, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowScore =  { 0, 0, 0, 0, 0x0100007f, 5678, 0, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceLowScore);
    AJ_AddRoutingNodeToResponseList(&serviceHighScore);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceHighScore.priority, service.priority) << "Priority not updated in response list";
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

TEST_F(DiscoveryTest, UpdateProtocolVersion)
{
    // Select between two routing nodes with different protocol versions.
    AJ_Service service;
    AJ_Service serviceOldProtocol = { 0, 0, 0, 0, 0x0100007f, 1234, 11, { 0, 0, 0, 0 } };
    AJ_Service serviceNewProtocol =  { 0, 0, 0, 0, 0x0100007f, 5678, 12, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceOldProtocol);
    AJ_AddRoutingNodeToResponseList(&serviceNewProtocol);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceNewProtocol.priority, service.priority) << "Priority not updated in the response list";
    EXPECT_EQ(serviceNewProtocol.pv, service.pv) << "Protocol version not updated in the response list";
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

TEST_F(DiscoveryTest, SelectPriorityListFullVarious)
{
    // Select correct routing node after adding best priority to a list that is full of various priorities
    AJ_Service service;
    AJ_Service serviceHigherScore =  { 0, 0, 0, 0, 0x0100007f, 1234, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore1 = { 0, 0, 0, 0, 0x0200007f, 2345, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore2 = { 0, 0, 0, 0, 0x0300007f, 3456, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore3 =  { 0, 0, 0, 0, 0x0400007f, 4567, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore4 =  { 0, 0, 0, 0, 0x0500007f, 5678, 0, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore2);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore3);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore4);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore1);
    AJ_AddRoutingNodeToResponseList(&serviceHigherScore);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceHigherScore.ipv4, service.ipv4) << "Wrong ipv4 address selected from the response list";
}

TEST_F(DiscoveryTest, SelectPriorityListFullEqual)
{
    // Select correct routing node after adding best priority to a list that is full of equal priorities
    AJ_Service service;
    AJ_Service serviceHigherScore =  { 0, 0, 0, 0, 0x0100007f, 1234, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore1 = { 0, 0, 0, 0, 0x0200007f, 5678, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore2 = { 0, 0, 0, 0, 0x0300007f, 5678, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore3 =  { 0, 0, 0, 0, 0x0400007f, 5678, 0, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore2);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore3);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore1);
    AJ_AddRoutingNodeToResponseList(&serviceHigherScore);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceHigherScore.ipv4, service.ipv4) << "Wrong ipv4 address selected from the response list";
}

TEST_F(DiscoveryTest, SelectPriorityListFullDoNotEvict)
{
    // Select correct routing node after attempting to add lesser score to a list that is full of various priorities
    AJ_Service service;
    AJ_Service serviceHigherScore =  { 0, 0, 0, 0, 0x0100007f, 1234, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore1 = { 0, 0, 0, 0, 0x0200007f, 2345, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore2 = { 0, 0, 0, 0, 0x0300007f, 3456, 0, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore3 =  { 0, 0, 0, 0, 0x0400007f, 4567, 0, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore2);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore1);
    AJ_AddRoutingNodeToResponseList(&serviceHigherScore);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore3);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceHigherScore.ipv4, service.ipv4) << "Wrong ipv4 address selected from the response list";
}

TEST_F(DiscoveryTest, SelectProtocolVersionListFullEqual)
{
    // Select correct routing node after adding better protocol version to a list that is full of equal protocol versi
    AJ_Service service;
    AJ_Service serviceHigherScore =  { 0, 0, 0, 0, 0x0100007f, 6789, 12, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore1 = { 0, 0, 0, 0, 0x0200007f, 5678, 11, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore2 = { 0, 0, 0, 0, 0x0300007f, 5678, 11, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore3 =  { 0, 0, 0, 0, 0x0400007f, 5678, 11, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore2);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore3);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore1);
    AJ_AddRoutingNodeToResponseList(&serviceHigherScore);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceHigherScore.ipv4, service.ipv4) << "Wrong ipv4 address selected from the response list";
}

TEST_F(DiscoveryTest, SelectProtocolVersionPriorityListFullEqual)
{
    // Select correct routing node after adding better protocol version and priority to a list that is full of equal protocol versi
    AJ_Service service;
    AJ_Service serviceHigherScore =  { 0, 0, 0, 0, 0x0100007f, 1234, 12, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore1 = { 0, 0, 0, 0, 0x0200007f, 5678, 11, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore2 = { 0, 0, 0, 0, 0x0300007f, 5678, 11, { 0, 0, 0, 0 } };
    AJ_Service serviceLowerScore3 =  { 0, 0, 0, 0, 0x0400007f, 5678, 11, { 0, 0, 0, 0 } };

    AJ_InitRoutingNodeResponselist();
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore2);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore3);
    AJ_AddRoutingNodeToResponseList(&serviceLowerScore1);
    AJ_AddRoutingNodeToResponseList(&serviceHigherScore);
    AJ_Status status = AJ_SelectRoutingNodeFromResponseList(&service);
    EXPECT_EQ(AJ_OK, status) << "Unable to select any routing node from the response list ";
    EXPECT_EQ(serviceHigherScore.ipv4, service.ipv4) << "Wrong ipv4 address selected from the response list";
}
