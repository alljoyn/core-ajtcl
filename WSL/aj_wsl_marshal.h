/**
 * @file Marshaling function declarations
 */
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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

#ifndef AJ_WSL_MARSHAL_H_
#define AJ_WSL_MARSHAL_H_

#include "aj_wsl_wmi.h"
#include "aj_wsl_spi_constants.h"
#include <stdarg.h>

/**
 * Marshal a list of arguments into a AJ_BufList.
 *
 * @param data      The AJ_BufList to contain the marshaled data
 * @param sig       The signature matching the parameters following it
 * @param ...       The arguments that will be marshaled into the AJ_BufList
 *                  in the order they appear.
 *
 * @return          1 If the data was successfully marshaled
 *                  0 If there was an error
 */
uint8_t WMI_MarshalArgsBuf(AJ_BufList* data, const char* sig, uint16_t size, va_list* argpp);

/**
 * Marshals the header onto an already existing packet.
 *
 * @param data      The AJ_BufList already containing the packet data
 */
void WMI_MarshalHeader(AJ_BufList* packet, uint8_t endpoint, uint8_t flags);

/**
 * Marshals an entire packet to send over SPI
 *
 * @param command   The command ID you are marshaling
 * @param AJ_BufList  An empty, malloc'ed buffer list to hold the packet data
 * @param ...       The list of arguments to put into the packet.
 *                  (note: the list of arguments must match the signature of the
 *                  packet you are trying to marshal. This includes, starting with,
 *                  the command ID followed by a 32 bit unsigned int (usually 0),
 *                  then the arguments for the packet.)
 *
 * @return          The size of the packet that was marshaled (not including header)
 *                  0 If there was an error
 */
void WSL_MarshalPacket(AJ_BufList* packet, wsl_wmi_command_list command, ...);

#endif /* AJ_WSL_MARSHAL_H_ */
