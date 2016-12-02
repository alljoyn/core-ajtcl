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
#define AJ_MODULE TEST_BASE64

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "aj_debug.h"
#include "alljoyn.h"
#include "aj_util.h"

uint8_t dbgTEST_BASE64 = 0;

static int test(char* input, char* output)
{
    AJ_Status status;
    int inputlen;
    int outputlen;
    char encode[1024];
    char decode[1024];

    inputlen = strlen(input);
    outputlen = strlen(output);

    status = AJ_RawToB64((uint8_t*) input, inputlen, encode, sizeof (encode));
    if (AJ_OK != status) {
        AJ_AlwaysPrintf(("FAILED STATUS\n"));
        return 1;
    }
    if (0 != strncmp(output, encode, outputlen)) {
        AJ_AlwaysPrintf(("FAILED ENCODE\n"));
        return 1;
    }

    status = AJ_B64ToRaw(output, outputlen, (uint8_t*) decode, sizeof (decode));
    if (AJ_OK != status) {
        AJ_AlwaysPrintf(("FAILED STATUS\n"));
        return 1;
    }
    if (0 != strncmp(input, decode, inputlen)) {
        AJ_AlwaysPrintf(("FAILED DECODE\n"));
        return 1;
    }

    return 0;
}

int AJ_Main(void)
{
    /*
     * put your test cases here.
     */

    if (test("This is a test.", "VGhpcyBpcyBhIHRlc3Qu")) {
        AJ_AlwaysPrintf(("FAILED\n"));
    } else {
        AJ_AlwaysPrintf(("PASSED\n"));
    }

    return 0;
}

#ifdef AJ_MAIN
int main(void)
{
    return AJ_Main();
}
#endif