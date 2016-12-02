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

#include <stdio.h>
#include <stdlib.h>

#include "alljoyn.h"
#include "aj_crypto.h"
#include "aj_debug.h"

static const uint8_t key[] = { 0xC6, 0xC4, 0xFC, 0xEF, 0x31, 0x85, 0xFB, 0x66, 0xAA, 0xB8, 0x62, 0xBC, 0x03, 0x76, 0xAB, 0xBE };

static uint8_t msg[1024];
static uint32_t nonce[2] = { 0x2AC45FAD, 0xD617159A };

int main(void)
{
    AJ_Status status = AJ_OK;
    size_t i;
    uint8_t cmp[1024];

    for (i = 0; i < sizeof(msg); ++i) {
        msg[i] = (uint8_t)(127 + i * 11 + i * 13 + i * 17);
    }

    for (i = 0; i < 10000; ++i) {
        uint8_t hdrLen;

        for (hdrLen = 10; hdrLen < 60; hdrLen += 3) {
            memcpy(cmp, msg, sizeof(msg));

            status = AJ_Encrypt_CCM(key, msg, sizeof(msg), hdrLen, 12, (const uint8_t*) nonce, sizeof(nonce));
            if (status != AJ_OK) {
                AJ_AlwaysPrintf(("Encryption failed (%d) for test #%zu\n", status, i));
                goto ErrorExit;
            }
            status = AJ_Decrypt_CCM(key, msg, sizeof(msg), hdrLen, 12, (const uint8_t*) nonce, sizeof(nonce));
            if (status != AJ_OK) {
                AJ_AlwaysPrintf(("Authentication failure (%d) for test #%zu\n", status, i));
                goto ErrorExit;
            }
            if (memcmp(cmp, msg, sizeof(msg)) != 0) {
                AJ_AlwaysPrintf(("Decrypt verification failure \n"));
                goto ErrorExit;
            }
            nonce[0] += 1;
        }
    }
    return 0;

ErrorExit:

    AJ_AlwaysPrintf(("AES CCM unit test FAILED\n"));
    return 1;
}