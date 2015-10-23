/**
 * @file Unit tests unmarshaling data in AJ_WSL.
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
#include "aj_util.h"

#include "aj_debug.h"
#include "../../WSL/aj_wsl_unmarshal.h"

/* SSID fishing2 [00:23:69:7e:bb:fe] RSSI=34 security=WPA2:CCMP */

static const uint8_t fishing2[] = {
    0x01, 0x02, 0xe9, 0x00, 0x08, 0x12, 0x04, 0x10, 0x00, 0x00, 0x00, 0x23, 0x85, 0x09, 0x02, 0x22, 0x00, 0x23, 0x69, 0x7e,
    0xbb, 0xfe, 0x00, 0x10, 0xb5, 0x6d, 0x44, 0xf9, 0xc7, 0x00, 0x00, 0x00, 0x64, 0x00, 0x31, 0x04, 0x00, 0x08, 0x66, 0x69,
    0x73, 0x68, 0x69, 0x6e, 0x67, 0x32, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x06, 0x30,
    0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00,
    0x00, 0x2a, 0x01, 0x00, 0x32, 0x04, 0x30, 0x48, 0x60, 0x6c, 0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff,
    0x7f, 0xdd, 0x0a, 0x00, 0x03, 0x7f, 0x04, 0x01, 0x00, 0x02, 0x00, 0x40, 0x00, 0xdd, 0x74, 0x00, 0x50, 0xf2, 0x04, 0x10,
    0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x23, 0x69, 0x7e, 0xbb, 0xfe, 0x10, 0x21, 0x00, 0x0c, 0x4c, 0x69,
    0x6e, 0x6b, 0x73, 0x79, 0x73, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x10, 0x23, 0x00, 0x07, 0x57, 0x52, 0x54, 0x35, 0x34, 0x47,
    0x32, 0x10, 0x24, 0x00, 0x07, 0x76, 0x31, 0x2e, 0x35, 0x2e, 0x30, 0x32, 0x10, 0x42, 0x00, 0x01, 0x30, 0x10, 0x54, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x07, 0x57, 0x52, 0x54, 0x35, 0x34, 0x47, 0x32,
    0x10, 0x08, 0x00, 0x02, 0x00, 0x84, 0x10, 0x3c, 0x00, 0x01, 0x01, 0x02, 0x06, 0x00, 0x00, 0x0c, 0x0a, 0x01, 0x00, 0x01,
    0x01, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t SEAQUICAP1[] = {
    0x01, 0x02, 0x7e, 0x01, 0x08, 0x0d, 0x04, 0x10, 0x00, 0x00, 0x2c, 0xb0, 0x6c, 0x09, 0x02, 0x31, 0x2c, 0xb0, 0x5d, 0x82,
    0xef, 0xb5, 0x00, 0x10, 0x76, 0xbe, 0x97, 0xa3, 0x08, 0x00, 0x00, 0x00, 0x64, 0x00, 0x31, 0x00, 0x00, 0x0b, 0x53, 0x45,
    0x41, 0x51, 0x55, 0x49, 0x43, 0x2d, 0x41, 0x50, 0x31, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x03,
    0x01, 0x01, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
    0xac, 0x02, 0x00, 0x00, 0x2a, 0x01, 0x02, 0x32, 0x04, 0x30, 0x48, 0x60, 0x6c, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01,
    0x01, 0x83, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00, 0xdd,
    0x1e, 0x00, 0x90, 0x4c, 0x33, 0xcc, 0x11, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x1a, 0xcc, 0x11, 0x1b, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd,
    0x1a, 0x00, 0x90, 0x4c, 0x34, 0x01, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x16, 0x01, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00,
    0xff, 0x7f, 0xdd, 0x0a, 0x00, 0x03, 0x7f, 0x04, 0x01, 0x00, 0x02, 0x00, 0x40, 0x00, 0xdd, 0x7c, 0x00, 0x50, 0xf2, 0x04,
    0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x2c, 0xb0, 0x5d, 0x82, 0xef, 0xb5, 0x10, 0x21, 0x00, 0x07, 0x4e,
    0x65, 0x74, 0x67, 0x65, 0x61, 0x72, 0x10, 0x23, 0x00, 0x08, 0x57, 0x4e, 0x44, 0x52, 0x33, 0x38, 0x30, 0x30, 0x10, 0x24,
    0x00, 0x02, 0x56, 0x31, 0x10, 0x42, 0x00, 0x04, 0x6e, 0x6f, 0x6e, 0x65, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50,
    0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x15, 0x57, 0x4e, 0x44, 0x52, 0x33, 0x38, 0x30, 0x30, 0x28, 0x57, 0x69, 0x72,
    0x65, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x41, 0x50, 0x29, 0x10, 0x08, 0x00, 0x02, 0x00, 0x86, 0x10, 0x3c, 0x00, 0x01, 0x03,
    0x02, 0x06, 0x00, 0x00, 0x0c, 0x0a, 0x01, 0x00, 0x01, 0x01, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t unknown[] = {
    0x01, 0x02, 0x48, 0x01, 0x08, 0x0f, 0x04, 0x10, 0x00, 0x00, 0x74, 0x44, 0x6c, 0x09, 0x02, 0x17, 0x74, 0x44, 0x01, 0x31,
    0x04, 0x6d, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x11, 0x04, 0x00, 0x12, 0x41, 0x70,
    0x70, 0x6c, 0x69, 0x65, 0x64, 0x52, 0x65, 0x73, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x01, 0x08, 0x82, 0x84,
    0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 0x01, 0x01, 0x2a, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x30, 0x14, 0x01, 0x00, 0x00,
    0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00, 0x32, 0x04, 0x0c,
    0x12, 0x18, 0x60, 0x2d, 0x1a, 0xfc, 0x18, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x16, 0x01, 0x08, 0x11, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x0e, 0x14, 0x00, 0x0a,
    0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00, 0x7f, 0x01, 0x01, 0xdd, 0x8b, 0x00, 0x50, 0xf2, 0x04,
    0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0xf6,
    0xbb, 0xf4, 0xbf, 0xf4, 0x2d, 0xe1, 0x45, 0xde, 0xf0, 0x48, 0x81, 0x85, 0x0a, 0xf8, 0xf9, 0x10, 0x21, 0x00, 0x0d, 0x4e,
    0x45, 0x54, 0x47, 0x45, 0x41, 0x52, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x10, 0x23, 0x00, 0x0a, 0x57, 0x4e, 0x44, 0x52,
    0x33, 0x37, 0x30, 0x30, 0x76, 0x33, 0x10, 0x24, 0x00, 0x0a, 0x57, 0x4e, 0x44, 0x52, 0x33, 0x37, 0x30, 0x30, 0x76, 0x33,
    0x10, 0x42, 0x00, 0x02, 0x30, 0x31, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x10, 0x11,
    0x00, 0x0c, 0x57, 0x69, 0x72, 0x65, 0x6c, 0x65, 0x73, 0x73, 0x41, 0x50, 0x30, 0x31, 0x10, 0x08, 0x00, 0x02, 0x00, 0x04,
    0x10, 0x3c, 0x00, 0x01, 0x03, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20, 0xdd, 0x09, 0x00, 0x10, 0x18,
    0x02, 0x00, 0xf0, 0x28, 0x00, 0x00, 0x02, 0x06, 0x00, 0x00, 0x0c, 0x0a, 0x01, 0x00, 0x01, 0x01, 0x02, 0x06, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t unknown2[] = {
    0x01, 0x02, 0x41, 0x01, 0x08, 0x15, 0x04, 0x10, 0x00, 0x00, 0x68, 0x7f, 0x85, 0x09, 0x02, 0x1a, 0x68, 0x7f, 0x74, 0x82,
    0x89, 0xd8, 0x00, 0x10, 0x15, 0xea, 0x0f, 0x01, 0x02, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x21, 0x04, 0x00, 0x09, 0x70, 0x65,
    0x72, 0x66, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x06,
    0x2a, 0x01, 0x00, 0x32, 0x04, 0x30, 0x48, 0x60, 0x6c, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x02, 0x00, 0x03,
    0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00, 0x2d, 0x1a, 0x4c, 0x10, 0x1b,
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3d, 0x16, 0x06, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x93, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44,
    0x00, 0x01, 0x02, 0x10, 0x41, 0x00, 0x01, 0x00, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x68, 0x7f, 0x74, 0x82, 0x89, 0xd8, 0x10, 0x21, 0x00, 0x13, 0x4c, 0x69, 0x6e,
    0x6b, 0x73, 0x79, 0x73, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x10, 0x23, 0x00, 0x07,
    0x57, 0x52, 0x54, 0x31, 0x32, 0x30, 0x4e, 0x10, 0x24, 0x00, 0x07, 0x76, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x34, 0x10, 0x42,
    0x00, 0x0c, 0x4a, 0x55, 0x54, 0x30, 0x30, 0x4b, 0x35, 0x31, 0x39, 0x33, 0x30, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06,
    0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x14, 0x57, 0x69, 0x72, 0x65, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x52,
    0x6f, 0x75, 0x74, 0x65, 0x72, 0x28, 0x57, 0x46, 0x41, 0x29, 0x10, 0x08, 0x00, 0x02, 0x00, 0x84, 0xdd, 0x09, 0x00, 0x03,
    0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f, 0xdd, 0x0a, 0x00, 0x03, 0x7f, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x06, 0xaa, 0x01, 0x02, 0x48, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};
int AJ_Main(void)
{
    WMI_Unmarshal2(fishing2);
    AJ_AlwaysPrintf(("==============================\n"));
    WMI_Unmarshal2(SEAQUICAP1);
    AJ_AlwaysPrintf(("==============================\n"));
    WMI_Unmarshal2(unknown);
    AJ_AlwaysPrintf(("==============================\n"));
    WMI_Unmarshal2(unknown2);
    AJ_AlwaysPrintf(("==============================\n"));
    return 1;
}