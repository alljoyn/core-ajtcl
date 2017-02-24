#ifndef _AJ_STATUS_H
#define _AJ_STATUS_H
/**
 * @file aj_status.h
 * @defgroup aj_status AllJoyn Status (Return) Codes
 * @{
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

/**
 * Status codes
 */
typedef enum {

    AJ_OK               = 0,  /**< Success status */
    AJ_ERR_NULL         = 1,  /**< Unexpected NULL pointer */
    AJ_ERR_UNEXPECTED   = 2,  /**< An operation was unexpected at this time */
    AJ_ERR_INVALID      = 3,  /**< A value was invalid */
    AJ_ERR_IO_BUFFER    = 4,  /**< An I/O buffer was invalid or in the wrong state */
    AJ_ERR_READ         = 5,  /**< An error while reading data from the network */
    AJ_ERR_WRITE        = 6,  /**< An error while writing data to the network */
    AJ_ERR_TIMEOUT      = 7,  /**< A timeout occurred */
    AJ_ERR_MARSHAL      = 8,  /**< Marshaling failed due to badly constructed message argument */
    AJ_ERR_UNMARSHAL    = 9,  /**< Unmarshaling failed due to a corrupt or invalid message */
    AJ_ERR_END_OF_DATA  = 10, /**< Not enough data */
    AJ_ERR_RESOURCES    = 11, /**< Insufficient memory to perform the operation */
    AJ_ERR_NO_MORE      = 12, /**< Attempt to unmarshal off the end of an array */
    AJ_ERR_SECURITY     = 13, /**< Authentication or decryption failed */
    AJ_ERR_CONNECT      = 14, /**< Network connect failed */
    AJ_ERR_UNKNOWN      = 15, /**< A unknown value */
    AJ_ERR_NO_MATCH     = 16, /**< Something didn't match */
    AJ_ERR_SIGNATURE    = 17, /**< Signature is not what was expected */
    AJ_ERR_DISALLOWED   = 18, /**< An operation was not allowed */
    AJ_ERR_FAILURE      = 19, /**< A failure has occurred */
    AJ_ERR_RESTART      = 20, /**< The OEM event loop must restart */
    AJ_ERR_LINK_TIMEOUT = 21, /**< The bus link is inactive too long */
    AJ_ERR_DRIVER       = 22, /**< An error communicating with a lower-layer driver */
    AJ_ERR_OBJECT_PATH  = 23, /**< Object path was not specified */
    AJ_ERR_BUSY         = 24, /**< An operation failed and should be retried later */
    AJ_ERR_DHCP         = 25  /**< A DHCP operation has failed */

} AJ_Status;

/**
 * @}
 */
#endif