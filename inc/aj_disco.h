#ifndef _AJ_DISCO_H
#define _AJ_DISCO_H

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

#include "aj_target.h"
#include "aj_bufio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Information about the remote service
 */
typedef struct _AJ_Service {
    uint8_t addrTypes;         /**< address type */
    uint16_t transportMask;    /**< restricts the transports the advertisement */
    uint16_t ipv4port;         /**< port number of ipv4 */
    uint16_t ipv6port;         /**< port number of ipv6 */
    uint32_t ipv4;             /**< ipv4 address */
    uint16_t priority;         /**< priority */
    uint32_t pv;               /**< protocol version */
    uint32_t ipv6[4];          /**< ipv6 address */

    uint16_t ipv4portUdp;      /**< port number of ipv4 */
    uint16_t ipv6portUdp;      /**< port number of ipv6 */
    uint32_t ipv4Udp;          /**< ipv4 address */
    uint32_t ipv6Udp[4];       /**< ipv6 address */
} AJ_Service;

/**
 * Discover a remote service
 *
 * @param prefix            The service name prefix
 * @param service           Information about the service that was found
 * @param timeout           How long to wait to discover the service
 * @param selectionTimeout  How long to wait to receive router responses
 *
 * @return                  Return AJ_Status
 */
AJ_Status AJ_Discover(const char* prefix, AJ_Service* service, uint32_t timeout, uint32_t selectionTimeout);

#ifdef __cplusplus
}
#endif

#endif