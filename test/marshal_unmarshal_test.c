/**
 * @file
 * Alljoyn client that marshals and unmarshals different data types.
 */

/******************************************************************************
 * Copyright (c) AllSeen Alliance. All rights reserved.
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

#define AJ_MODULE MARSHAL_UNMARSHAL

#include <stdio.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>


#ifndef bool    /* These tests were written to use stdbool.h, but VS2012 does not support it. */
#define bool int
#define false (0)
#define true (1)
#endif


#define CONNECT_ATTEMPTS   10
static const char ServiceName[] = "org.datatypes.test";
static const char ServicePath[] = "/datatypes";
static const uint16_t ServicePort = 25;

/*
 * Buffer to hold the full service name. This buffer must be big enough to hold
 * a possible 255 characters plus a null terminator (256 bytes)
 */
static char fullServiceName[AJ_MAX_SERVICE_NAME_SIZE];

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
uint8_t dbgMARSHAL_UNMARSHAL = 0;

/**
 * The interface name followed by the method signatures.
 *
 * See also .\inc\aj_introspect.h
 */
static const char* const sampleInterface[] = {
    "org.datatypes.test.interface",   /* The first entry is the interface name. */
    "?byte inStr<y outStr>y", /* Method at index 1. */
    "?int inStr<i outStr>i",
    "?unsignedint inStr<u outStr>u",
    "?double inStr<d outStr>d",
    "?bool inStr<b outStr>b",
    "?string inStr<s outStr>s",
    "?uint16 inStr<q outStr>q",
    "?int16 inStr<n outStr>n",
    "?uint64 inStr<t outStr>t",
    "?int64 inStr<x outStr>x",
    "?struct inStr<(yiudbsqnxt) outStr>(yiudbsqnxt)",
    "?dictionary inStr<a{uv} outStr>a{uv}",
    "?bytearray inStr<ay outStr>ay",
    "?intarray inStr<ai outStr>ai",
    "?unsignedintarray inStr<au outStr>au",
    "?doublearray inStr<ad outStr>ad",
    "?boolarray inStr<ab outStr>ab",
    "?stringarray inStr<as outStr>as",
    "?uint16array inStr<aq outStr>aq",
    "?int16array inStr<an outStr>an",
    "?uint64array inStr<at outStr>at",
    "?int64array inStr<ax outStr>ax",
    "?arrayofstruct inStr<a(is) outStr>a(is)",
    "?nestedstruct inStr<(y(iu)) outStr>(y(iu))",
    NULL
};

static const char* const paddingInterface[] = {
    "org.datatypes.test.padding.interface",   /* The first entry is the interface name. */
    "?paddingtest1 inStr<(yqut) outStr>(yqut)", /* Method at index 1. */
    "?paddingtest2 inStr<(yqtu) outStr>(yqtu)",
    "?paddingtest3 inStr<(yuqt) outStr>(yuqt)",
    "?paddingtest4 inStr<(yutq) outStr>(yutq)",
    "?paddingtest5 inStr<(ytqu) outStr>(ytqu)",
    "?paddingtest6 inStr<(ytuq) outStr>(ytuq)",
    "?paddingtest7 inStr<(qyut) outStr>(qyut)",
    "?paddingtest8 inStr<(qytu) outStr>(qytu)",
    "?paddingtest9 inStr<(uyqt) outStr>(uyqt)",
    "?paddingtest10 inStr<(tyqu) outStr>(tyqu)",
    NULL
};

/**
 * A NULL terminated collection of all interfaces.
 */
static const AJ_InterfaceDescription sampleInterfaces[] = {
    sampleInterface,
    paddingInterface,
    NULL
};

/**
 * Objects implemented by the application. The first member in the AJ_Object structure is the path.
 * The second is the collection of all interfaces at that path.
 */
static const AJ_Object AppObjects[] = {
    { ServicePath, sampleInterfaces },
    { NULL }
};

/*Service*/
#define BASIC_SERVICE_BYTE AJ_APP_MESSAGE_ID(0, 0, 0)
#define BASIC_SERVICE_INT AJ_APP_MESSAGE_ID(0, 0, 1)
#define BASIC_SERVICE_UNSIGNED_INT AJ_APP_MESSAGE_ID(0, 0, 2)
#define BASIC_SERVICE_DOUBLE AJ_APP_MESSAGE_ID(0, 0, 3)
#define BASIC_SERVICE_BOOL AJ_APP_MESSAGE_ID(0, 0, 4)
#define BASIC_SERVICE_STRING AJ_APP_MESSAGE_ID(0, 0, 5)
#define BASIC_SERVICE_UINT16 AJ_APP_MESSAGE_ID(0, 0, 6)
#define BASIC_SERVICE_INT16 AJ_APP_MESSAGE_ID(0, 0, 7)
#define BASIC_SERVICE_UINT64 AJ_APP_MESSAGE_ID(0, 0, 8)
#define BASIC_SERVICE_INT64 AJ_APP_MESSAGE_ID(0, 0, 9)
#define BASIC_SERVICE_STRUCT AJ_APP_MESSAGE_ID(0, 0, 10)
#define BASIC_SERVICE_DICT AJ_APP_MESSAGE_ID(0, 0, 11)
#define BASIC_SERVICE_BYTE_ARRAY AJ_APP_MESSAGE_ID(0, 0, 12)
#define BASIC_SERVICE_INT_ARRAY AJ_APP_MESSAGE_ID(0, 0, 13)
#define BASIC_SERVICE_UINT_ARRAY AJ_APP_MESSAGE_ID(0, 0, 14)
#define BASIC_SERVICE_DOUBLE_ARRAY AJ_APP_MESSAGE_ID(0, 0, 15)
#define BASIC_SERVICE_BOOL_ARRAY AJ_APP_MESSAGE_ID(0, 0, 16)
#define BASIC_SERVICE_STRING_ARRAY AJ_APP_MESSAGE_ID(0, 0, 17)
#define BASIC_SERVICE_UINT16_ARRAY AJ_APP_MESSAGE_ID(0, 0, 18)
#define BASIC_SERVICE_INT16_ARRAY AJ_APP_MESSAGE_ID(0, 0, 19)
#define BASIC_SERVICE_UINT64_ARRAY AJ_APP_MESSAGE_ID(0, 0, 20)
#define BASIC_SERVICE_INT64_ARRAY AJ_APP_MESSAGE_ID(0, 0, 21)
#define BASIC_SERVICE_STRUCT_ARRAY AJ_APP_MESSAGE_ID(0, 0, 22)
#define BASIC_SERVICE_NESTED_STRUCT AJ_APP_MESSAGE_ID(0, 0, 23)

/*Client*/
#define BASIC_SERVICE_BYTE_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 0)
#define BASIC_SERVICE_INT_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 1)
#define BASIC_SERVICE_UNSIGNED_INT_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 2)
#define BASIC_SERVICE_DOUBLE_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 3)
#define BASIC_SERVICE_BOOL_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 4)
#define BASIC_SERVICE_STRING_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 5)
#define BASIC_SERVICE_UINT16_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 6)
#define BASIC_SERVICE_INT16_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 7)
#define BASIC_SERVICE_UINT64_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 8)
#define BASIC_SERVICE_INT64_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 9)
#define BASIC_SERVICE_STRUCT_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 10)
#define BASIC_SERVICE_DICT_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 11)
#define BASIC_SERVICE_BYTE_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 12)
#define BASIC_SERVICE_INT_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 13)
#define BASIC_SERVICE_UINT_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 14)
#define BASIC_SERVICE_DOUBLE_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 15)
#define BASIC_SERVICE_BOOL_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 16)
#define BASIC_SERVICE_STRING_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 17)
#define BASIC_SERVICE_UINT16_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 18)
#define BASIC_SERVICE_INT16_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 19)
#define BASIC_SERVICE_UINT64_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 20)
#define BASIC_SERVICE_INT64_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 21)
#define BASIC_SERVICE_STRUCT_ARRAY_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 22)
#define BASIC_SERVICE_NESTED_STRUCT_CLIENT AJ_PRX_MESSAGE_ID(0, 0, 23)

/*Service*/
#define BASIC_SERVICE_PADDING_1 AJ_APP_MESSAGE_ID(0, 1, 0)
#define BASIC_SERVICE_PADDING_2 AJ_APP_MESSAGE_ID(0, 1, 1)
#define BASIC_SERVICE_PADDING_3 AJ_APP_MESSAGE_ID(0, 1, 2)
#define BASIC_SERVICE_PADDING_4 AJ_APP_MESSAGE_ID(0, 1, 3)
#define BASIC_SERVICE_PADDING_5 AJ_APP_MESSAGE_ID(0, 1, 4)
#define BASIC_SERVICE_PADDING_6 AJ_APP_MESSAGE_ID(0, 1, 5)
#define BASIC_SERVICE_PADDING_7 AJ_APP_MESSAGE_ID(0, 1, 6)
#define BASIC_SERVICE_PADDING_8 AJ_APP_MESSAGE_ID(0, 1, 7)
#define BASIC_SERVICE_PADDING_9 AJ_APP_MESSAGE_ID(0, 1, 8)
#define BASIC_SERVICE_PADDING_10 AJ_APP_MESSAGE_ID(0, 1, 9)

/*Client*/
#define BASIC_CLIENT_PADDING_1 AJ_PRX_MESSAGE_ID(0, 1, 0)
#define BASIC_CLIENT_PADDING_2 AJ_PRX_MESSAGE_ID(0, 1, 1)
#define BASIC_CLIENT_PADDING_3 AJ_PRX_MESSAGE_ID(0, 1, 2)
#define BASIC_CLIENT_PADDING_4 AJ_PRX_MESSAGE_ID(0, 1, 3)
#define BASIC_CLIENT_PADDING_5 AJ_PRX_MESSAGE_ID(0, 1, 4)
#define BASIC_CLIENT_PADDING_6 AJ_PRX_MESSAGE_ID(0, 1, 5)
#define BASIC_CLIENT_PADDING_7 AJ_PRX_MESSAGE_ID(0, 1, 6)
#define BASIC_CLIENT_PADDING_8 AJ_PRX_MESSAGE_ID(0, 1, 7)
#define BASIC_CLIENT_PADDING_9 AJ_PRX_MESSAGE_ID(0, 1, 8)
#define BASIC_CLIENT_PADDING_10 AJ_PRX_MESSAGE_ID(0, 1, 9)

struct PaddingStruct {
    uint8_t byte;
    uint16_t uint16;
    uint32_t uint32;
    uint64_t uint64;
};

struct SampleStruct {
    int intVar;
    unsigned char byte;
    int int32;
    unsigned int uint32;
    double doubleValue;
    bool boolValue;
    char* stringValue;
    uint16_t uint16;
    int16_t int16;
    int64_t int64;
    uint64_t uint64;
};

struct ArrayStruct {
    int intVar;
    const char* stringValue;
};

/*
 * Use async version of API for reply
 */
static uint8_t asyncForm = FALSE;

/* All times are expressed in milliseconds. */
#define CONNECT_TIMEOUT     (1000 * 60)
#define UNMARSHAL_TIMEOUT   (1000 * 5)
#define SLEEP_TIME          (1000 * 2)
#define METHOD_TIMEOUT     (100 * 10)

/*******************************************************************************/
/*******************************************************************************/
/*                          METHOD CALLS                                       */
/*******************************************************************************/
/*******************************************************************************/

void ByteMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    unsigned char inputByte = 125;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_BYTE_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "y", inputByte);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("ByteMethodCall() resulted in a status of 0x%04x.\n", status));
}

void IntMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int inputInt = 100;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_INT_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "i", inputInt);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("IntMethodCall() resulted in a status of 0x%04x.\n", status));
}

void UnsignedIntMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    unsigned int inputInt = 4294967201;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_UNSIGNED_INT_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "u", inputInt);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("UnsignedIntMethodCall() resulted in a status of 0x%04x.\n", status));
}

void DoubleMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    double inputDouble = -4294967201986;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_DOUBLE_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "d", inputDouble);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("DoubleMethodCall() resulted in a status of 0x%04x.\n", status));
}

void BooleanMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    bool inputBool = false;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_BOOL_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "b", inputBool);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("BooleanMethodCall() resulted in a status of 0x%04x.\n", status));
}

void StringMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    const char* inputString = "This is a cool string";

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_STRING_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", inputString);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("BooleanMethodCall() resulted in a status of 0x%04x.\n", status));
}

void UInt16MethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    uint16_t inputUInt16 = 60500;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_UINT16_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "q", inputUInt16);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("UInt16MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Int16MethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    uint16_t inputUInt16 = -15236;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_INT16_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "n", inputUInt16);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Int16MethodCall() resulted in a status of 0x%04x.\n", status));
}

void UInt64MethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    uint64_t inputUInt64 = 18446744073709551610ULL;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_UINT64_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "t", inputUInt64);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("UInt64MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Int64MethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int64_t inputUInt64 = -92233720368547758LL;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_INT64_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "x", inputUInt64);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Int64MethodCall() resulted in a status of 0x%04x.\n", status));
}

void StructMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    struct SampleStruct structData;

    structData.byte = 254;
    structData.int32 = -65541;
    structData.uint32 = 65541;
    structData.doubleValue = 3.14908765;
    structData.boolValue = false;
    structData.stringValue = (char*)"Hello Struct";
    structData.uint16 = 65535;
    structData.int16 = -32768;
    structData.int64 = -5223372036854775808LL;
    structData.uint64 = 6223372036854775808ULL;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_STRUCT_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(yiudbsqnxt)", structData.byte, structData.int32,
                                structData.uint32, structData.doubleValue, structData.boolValue, structData.stringValue,
                                structData.uint16, structData.int16, structData.int64, structData.uint64);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("StructMethodCall() resulted in a status of 0x%04x.\n", status));
}

void DictionaryMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message dict;
    AJ_Arg array1;

    uint32_t key = 1;
    uint32_t val = 2134;

    status = AJ_MarshalMethodCall(bus, &dict, BASIC_SERVICE_DICT_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalContainer(&dict, &array1, AJ_ARG_ARRAY);
    }

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&dict, "{uv}", key, "u", val);
    }
    if (status == AJ_OK) {
        status = AJ_MarshalCloseContainer(&dict, &array1);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&dict);
    }

    AJ_InfoPrintf(("DictionaryMethodCall resulted in a status of 0x%04x.\n", status));
}

void ByteArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    uint8_t inputArray [5] = { 57, 125, 79, 100, 12 };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_BYTE_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        //status = AJ_MarshalContainer(&msg, &inputArray, AJ_ARG_ARRAY);
        status = AJ_MarshalArgs(&msg, "ay", inputArray, sizeof(inputArray));
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("ByteArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void IntArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    AJ_Arg array1;
    int inputArray [5] = { 1552, -1, -547, 101, 5269 };
    int i;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_INT_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "i", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array1);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("IntArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void UnsignedIntArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    AJ_Arg array;
    unsigned int inputArray [5] = { 1552, 1, 5562447, 101, 565269 };
    int i;
    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_UINT_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "u", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("UnsignedIntArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void DoubleArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    double inputArray [5] = { 789.66, 1.0009, 5562447, 175.569, -78.2 };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_DOUBLE_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "d", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("DoubleArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}


void BoolArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    bool inputArray [5] = { true, true, true, true, false };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_BOOL_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "b", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("BoolArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void StringArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    const char* inputArray [5] = { "Hello", "Hola Amigos", "Alljoyn", "Is Awesome", "IoT :)" };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_STRING_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "s", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("StringArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void UnsignedInt16ArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {

    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    uint16_t inputArray [5] = { 1564, 0, 4612, 12546, 125 };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_UINT16_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "q", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("UnsignedInt16ArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void Int16ArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    int16_t inputArray [5] = { 1564, 0, 4612, -13546, -125 };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_INT16_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "n", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("UnsignedInt16ArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void UnsignedInt64ArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    uint64_t inputArray [5] = { 1565151234, 1000000, 4656412, 1221546, 125 };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_UINT64_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "t", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("UnsignedInt64ArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void Int64ArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    int64_t inputArray [5] = { 1564562, 1145550, 4612, -2213546, -12655 };

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_INT64_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 5; ++i) {
            status = AJ_MarshalArgs(&msg, "x", inputArray[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Int64ArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void StructArrayMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    int i;
    AJ_Arg array;
    struct ArrayStruct struct1;
    struct ArrayStruct struct2;
    struct ArrayStruct struct3;
    struct ArrayStruct inputArray [3];

    struct1.intVar = 509;
    struct1.stringValue = "Le First Line";

    struct2.intVar = 59;
    struct2.stringValue = "Le Struct Line";

    struct3.intVar = 3409;
    struct3.stringValue = "Le AllIoT Cool Line";

    inputArray[0] =  struct1;
    inputArray[1] = struct2;
    inputArray[2] = struct3;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_STRUCT_ARRAY_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    AJ_MarshalContainer(&msg, &array, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < 3; i++) {
            status = AJ_MarshalArgs(&msg, "(is)", inputArray[i].intVar, inputArray[i].stringValue);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&msg, &array);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("StructArrayMethodCall() resulted in a status of 0x%04x.\n", status));
}

void NestedStructMethodCall(AJ_BusAttachment* bus, uint32_t sessionId) {
    AJ_Status status;
    AJ_Message msg;
    uint8_t byte = 110;
    unsigned int uIntVal = 5894;
    int intVal = -4512;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_SERVICE_NESTED_STRUCT_CLIENT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(y(iu))", byte, intVal, uIntVal);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("NestedStructMethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding1MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_1, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(yqut)", structP->byte, structP->uint16, structP->uint32, structP->uint64);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding1MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding2MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_2, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(yqtu)", structP->byte, structP->uint16, structP->uint64, structP->uint32);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding2MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding3MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_3, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(yuqt)", structP->byte, structP->uint32, structP->uint16,  structP->uint64);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding3MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding4MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_4, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(yutq)", structP->byte, structP->uint32, structP->uint64, structP->uint16);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding4MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding5MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_5, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(ytqu)", structP->byte, structP->uint64, structP->uint16, structP->uint32);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding5MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding6MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_6, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(ytuq)", structP->byte, structP->uint64, structP->uint32, structP->uint16);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding6MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding7MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_7, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(qyut)", structP->uint16, structP->byte, structP->uint32, structP->uint64);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding7MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding8MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_8, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(qytu)", structP->uint16, structP->byte, structP->uint64,  structP->uint32);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding8MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding9MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_9, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(uyqt)", structP->uint32, structP->byte, structP->uint16, structP->uint64);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding9MethodCall() resulted in a status of 0x%04x.\n", status));
}

void Padding10MethodCall(AJ_BusAttachment* bus, uint32_t sessionId, struct PaddingStruct* structP) {
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_PADDING_10, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "(tyqu)", structP->uint64, structP->byte,  structP->uint16, structP->uint32);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_InfoPrintf(("Padding10MethodCall() resulted in a status of 0x%04x.\n", status));
}

/*******************************************************************************/
/*******************************************************************************/
/*                          APP HANDLERS                                       */
/*******************************************************************************/
/*******************************************************************************/
static AJ_Status AppHandleByte(AJ_Message* msg) {
    unsigned char value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "y", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_BYTE, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleInt(AJ_Message* msg) {
    int value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "i", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_INT32, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleUnsignedInt(AJ_Message* msg) {
    unsigned int value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "u", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_UINT32, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleDouble(AJ_Message* msg) {
    double value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "d", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_DOUBLE, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleBoolean(AJ_Message* msg) {
    bool value;
    AJ_Message reply;

    AJ_UnmarshalArgs(msg, "b", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "b", value);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleString(AJ_Message* msg) {
#define BUFFER_SIZE 256
    const char* value;
    char buffer[BUFFER_SIZE];
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "s", &value);

    /* We have the arguments. Now do the concatenation. */
    strncpy(buffer, value, BUFFER_SIZE);
    buffer[BUFFER_SIZE - 1] = '\0';

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_STRING, 0, &buffer, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
 #undef BUFFER_SIZE
}

static AJ_Status AppHandleUInt16(AJ_Message* msg) {
    uint16_t value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "q", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_UINT16, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleInt16(AJ_Message* msg) {
    int16_t value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "n", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_INT16, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleUInt64(AJ_Message* msg) {
    uint64_t value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "t", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_UINT64, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleInt64(AJ_Message* msg) {
    int64_t value = 0;
    AJ_Message reply;
    AJ_Arg replyArg;

    AJ_UnmarshalArgs(msg, "x", &value);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_InitArg(&replyArg, AJ_ARG_INT64, 0, &value, 0);
    AJ_MarshalArg(&reply, &replyArg);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleStruct(AJ_Message* msg) {
    struct SampleStruct structData;
    AJ_Message reply;

    AJ_UnmarshalArgs(msg, "(yiudbsqnxt)", &structData.byte, &structData.int32, &structData.uint32,
                     &structData.doubleValue, &structData.boolValue, &structData.stringValue, &structData.uint16,
                     &structData.int16, &structData.int64, &structData.uint64);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(yiudbsqnxt)", structData.byte, structData.int32,
                   structData.uint32, structData.doubleValue, structData.boolValue, structData.stringValue,
                   structData.uint16, structData.int16, structData.int64, structData.uint64);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleDictionary(AJ_Message* msg) {
    AJ_Message reply;
    unsigned int key;
    unsigned int value;
    AJ_Arg array;
    AJ_Arg replyArray;
    AJ_UnmarshalContainer(msg, &array, AJ_ARG_ARRAY);
    AJ_UnmarshalArgs(msg, "{uv}", &key, "u", &value);
    AJ_UnmarshalCloseContainer(msg, &array);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &replyArray, AJ_ARG_ARRAY);

    AJ_MarshalArgs(&reply, "{uv}", key, "u", value);

    AJ_MarshalCloseContainer(&reply, &replyArray);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleByteArray(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t* value;
    size_t size;
    AJ_UnmarshalArgs(msg, "ay", (const uint8_t**)&value, &size);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "ay", value, size);

    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleIntArray(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    int* value  = malloc(sizeof(int));
    int i;
    size_t size = 0;
    AJ_Arg arg1;

    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);

    while (status == AJ_OK) {
        status = AJ_UnmarshalArgs(msg, "i", &value[size]);
        if (status == AJ_OK) {
            value = realloc(value, (size + 2) * sizeof(int));
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "i", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleUnsignedIntArray(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    unsigned int* value  = malloc(sizeof(unsigned int));
    size_t size = 0;
    AJ_Arg arg1;
    int i;

    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);

    while (status == AJ_OK) {
        status = AJ_UnmarshalArgs(msg, "u", &value[size]);
        if (status == AJ_OK) {
            value = realloc(value, (size + 2) * sizeof(int));
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "u", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleDoubleArray(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    double* value = malloc(1 * sizeof(double));
    size_t size = 0;
    AJ_Arg arg1;
    int i;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        value = realloc(value, sizeof(double) * (size + 1));

        status = AJ_UnmarshalArgs(msg, "d", &value[size]);
        if (status == AJ_OK) {
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "d", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleBoolArray(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    bool* value = malloc(1 * sizeof(bool));
    size_t size = 0;
    AJ_Arg arg1;
    int i;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        value = realloc(value, sizeof(bool) * (size + 1));

        status = AJ_UnmarshalArgs(msg, "b", &value[size]);
        if (status == AJ_OK) {
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "b", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleStringArray(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    char** value = malloc(1 * sizeof(char*));
    size_t size = 0;
    int i;
    AJ_Arg arg1;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        value = realloc(value, sizeof(char*) * (size + 1));

        status = AJ_UnmarshalArgs(msg, "s", &value[size]);
        if (status == AJ_OK) {
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "s", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleUnsignedInt16Array(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    uint16_t* value = malloc(1 * sizeof(uint16_t));
    size_t size = 0;
    AJ_Arg arg1;
    int i;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        value = realloc(value, sizeof(uint16_t) * (size + 1));

        status = AJ_UnmarshalArgs(msg, "q", &value[size]);
        if (status == AJ_OK) {
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "q", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleInt16Array(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    int16_t* value = malloc(1 * sizeof(int16_t));
    size_t size = 0;
    AJ_Arg arg1;
    int i;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        value = realloc(value, sizeof(int16_t) * (size + 1));

        status = AJ_UnmarshalArgs(msg, "n", &value[size]);
        if (status == AJ_OK) {
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "n", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}
static AJ_Status AppHandleUnsignedInt64Array(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    uint64_t* value = malloc(1 * sizeof(uint64_t));
    size_t size = 0;
    int i;
    AJ_Arg arg1;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        value = realloc(value, sizeof(uint64_t) * (size + 1));

        status = AJ_UnmarshalArgs(msg, "t", &value[size]);
        if (status == AJ_OK) {
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "t", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleInt64Array(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    int64_t* value = malloc(1 * sizeof(int64_t));
    size_t size = 0;
    int i;
    AJ_Arg arg1;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        value = realloc(value, sizeof(int64_t) * (size + 1));

        status = AJ_UnmarshalArgs(msg, "x", &value[size]);
        if (status == AJ_OK) {
            size++;
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "x", value[i]);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleStructArray(AJ_Message* msg) {
    AJ_Message reply;
    AJ_Status status;
    struct ArrayStruct* value = malloc(1 * sizeof(struct ArrayStruct));
    size_t size = 0;
    int i;
    AJ_Arg arg1;
    status = AJ_UnmarshalContainer(msg, &arg1, AJ_ARG_ARRAY);


    while (status == AJ_OK) {
        status = AJ_UnmarshalArgs(msg, "(is)", &value[size].intVar, &value[size].stringValue);
        if (status == AJ_OK) {
            size++;
            value = realloc(value, sizeof(struct ArrayStruct) * (size + 1));
        }
    }
    /*
     * We expect AJ_ERR_NO_MORE
     */
    if (status == AJ_ERR_NO_MORE) {
        status = AJ_OK;
    }

    AJ_UnmarshalCloseContainer(msg, &arg1);

    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }

    AJ_MarshalContainer(&reply, &arg1, AJ_ARG_ARRAY);

    if (status == AJ_OK) {
        for (i = 0; i < size; ++i) {
            status = AJ_MarshalArgs(&reply, "(is)", value[i].intVar, value[i].stringValue);
        }
    }

    if (status == AJ_OK) {
        AJ_MarshalCloseContainer(&reply, &arg1);
    }

    status = AJ_DeliverMsg(&reply);
    free(value);
    return status;
}

static AJ_Status AppHandleNestedStruct(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    unsigned int uIntVal;
    int intVal;

    AJ_UnmarshalArgs(msg, "(y(iu))", &byte, &intVal, &uIntVal);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(y(iu))", byte, intVal, uIntVal);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding1(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(yqut)", &byte, &uint16Val, &uint32Val, &uint64Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(yqut)", byte, uint16Val, uint32Val, uint64Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding2(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(yqtu)", &byte, &uint16Val, &uint64Val, &uint32Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(yqtu)", byte, uint16Val, uint64Val, uint32Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding3(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(yuqt)", &byte, &uint32Val, &uint16Val, &uint64Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(yuqt)", byte, uint32Val, uint16Val, uint64Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding4(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(yutq)", &byte, &uint32Val, &uint64Val, &uint16Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(yutq)", byte, uint32Val, uint64Val, uint16Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding5(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(ytqu)", &byte, &uint64Val, &uint16Val, &uint32Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(ytqu)", byte, uint64Val, uint16Val, uint32Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding6(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(ytuq)", &byte, &uint64Val, &uint32Val, &uint16Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(ytuq)", byte, uint64Val, uint32Val, uint16Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding7(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(qyut)", &uint16Val, &byte, &uint32Val, &uint64Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(qyut)", uint16Val, byte, uint32Val, uint64Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding8(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(qytu)", &uint16Val, &byte, &uint64Val, &uint32Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(qytu)", uint16Val, byte, uint64Val, uint32Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding9(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(uyqt)", &uint32Val, &byte, &uint16Val, &uint64Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(uyqt)", uint32Val, byte, uint16Val, uint64Val);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandlePadding10(AJ_Message* msg) {
    AJ_Message reply;
    uint8_t byte;
    uint16_t uint16Val;
    uint32_t uint32Val;
    uint64_t uint64Val;

    AJ_UnmarshalArgs(msg, "(tyqu)", &uint64Val, &byte, &uint16Val, &uint32Val);
    if (asyncForm) {
        AJ_MsgReplyContext replyCtx;
        AJ_CloseMsgAndSaveReplyContext(msg, &replyCtx);
        AJ_MarshalReplyMsgAsync(&replyCtx, &reply);
    } else {
        AJ_MarshalReplyMsg(msg, &reply);
    }
    AJ_MarshalArgs(&reply, "(tyqu)", uint64Val, byte, uint16Val, uint32Val);
    return AJ_DeliverMsg(&reply);
}

int AJ_ClientMain(bool padding) {
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint8_t done = FALSE;
    uint32_t sessionId = 0;
    struct PaddingStruct paddingStruct;

    if (padding) {
        paddingStruct.byte = 10;
        paddingStruct.uint16 = 10589;
        paddingStruct.uint32 = 68254;
        paddingStruct.uint64 = 9845612;
    }
    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();
    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(NULL, AppObjects);

    /***********************************************************************************************/
    /* Int*/
    /***********************************************************************************************/
    while (!done) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartClientByName(&bus,
                                          NULL,
                                          CONNECT_TIMEOUT,
                                          FALSE,
                                          ServiceName,
                                          ServicePort,
                                          &sessionId,
                                          NULL,
                                          fullServiceName);

            if (status == AJ_OK) {
                AJ_InfoPrintf(("StartClient returned %d, sessionId=%u.\n", status, sessionId));
                connected = TRUE;
                AJ_AlwaysPrintf(("Method call  %s \n", "Int"));
                IntMethodCall(&bus, sessionId);
            } else {
                AJ_InfoPrintf(("StartClient returned 0x%04x.\n", status));
                break;
            }
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_REPLY_ID(BASIC_SERVICE_INT_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        int valueReturned = *arg.val.v_int32;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%i'.\n", fullServiceName, "interface",
                                         ServicePath, valueReturned));
                        //done = TRUE;
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        IntMethodCall(&bus, sessionId);
                    }
                } else {
                    const int valueReturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "y", &valueReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%i)\n", msg.error, valueReturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    //done = TRUE;
                }

                /*Byte Method Call*/
                AJ_AlwaysPrintf(("Method call  %s \n", "Byte"));
                ByteMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /* Byte*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_BYTE_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        const unsigned char byte = *arg.val.v_byte;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u'.\n", fullServiceName, "interface",
                                         ServicePath, byte));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        ByteMethodCall(&bus, sessionId);
                    }
                } else {
                    const uint8_t value = 0;
                    if (AJ_UnmarshalArgs(&msg, "y", &value) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, value));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                /*Unsigned int method call*/
                AJ_AlwaysPrintf(("Method call  %s \n", "Unsigned Int"));
                UnsignedIntMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Unsigned int */
            /************************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_UNSIGNED_INT_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        unsigned int uintreturned = *arg.val.v_uint32;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u'.\n", fullServiceName, "interface",
                                         ServicePath, uintreturned));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        UnsignedIntMethodCall(&bus, sessionId);
                    }
                } else {
                    const unsigned int uintreturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "u", &uintreturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, uintreturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                /*Double Method Call*/
                AJ_AlwaysPrintf(("Method call  %s \n", "Double"));
                DoubleMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Double*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_DOUBLE_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        double doubleReturned = *arg.val.v_double;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%f'.\n", fullServiceName, "interface",
                                         ServicePath, doubleReturned));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        DoubleMethodCall(&bus, sessionId);
                    }
                } else {
                    const double doubleReturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "u", &doubleReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, doubleReturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                /*Bool Method Call*/
                AJ_AlwaysPrintf(("Method call  %s \n", "Boolean"));
                BooleanMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Bool*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_BOOL_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        bool boolReturned = *arg.val.v_bool;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%s'.\n", fullServiceName, "interface",
                                         ServicePath, boolReturned ? "TRUE" : "FALSE"));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        BooleanMethodCall(&bus, sessionId);
                    }
                } else {
                    const bool boolReturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "b", &boolReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%s)\n", msg.error, boolReturned ? "TRUE" : "FALSE"));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                /*String method Call*/
                StringMethodCall(&bus, sessionId);
                AJ_AlwaysPrintf(("Method call  %s \n", "String"));
                break;

            /***********************************************************************************************/
            /*String*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_STRING_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        const char* stringReturned = arg.val.v_string;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%s'.\n", fullServiceName, "interface",
                                         ServicePath, stringReturned));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        StringMethodCall(&bus, sessionId);
                    }
                } else {
                    const char* stringReturned = "";
                    if (AJ_UnmarshalArgs(&msg, "s", &stringReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%s)\n", msg.error, stringReturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Unsigned Int 16"));
                UInt16MethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Unsigned Int 16*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_UINT16_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        uint16_t uintReturned = *arg.val.v_uint16;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u'.\n", fullServiceName, "interface",
                                         ServicePath, uintReturned));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        UInt16MethodCall(&bus, sessionId);
                    }
                } else {
                    const uint16_t uintReturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "q", &uintReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, uintReturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Int 16"));
                Int16MethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Int 16*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_INT16_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        int16_t intReturned = *arg.val.v_int16;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%d'.\n", fullServiceName, "interface",
                                         ServicePath, intReturned));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Int16MethodCall(&bus, sessionId);
                    }
                } else {
                    const int16_t intReturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "n", &intReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, intReturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Unsigned Int 64"));
                UInt64MethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Unsigned Int 64*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_UINT64_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        uint64_t uintReturned = *arg.val.v_uint64;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%llu'.\n", fullServiceName, "interface",
                                         ServicePath, uintReturned));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        UInt64MethodCall(&bus, sessionId);
                    }
                } else {
                    const uint16_t uintReturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "t", &uintReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%llu)\n", msg.error, uintReturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Int 64"));
                Int64MethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Int 64*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_INT64_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        int64_t intReturned = *arg.val.v_int64;
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%lld'.\n", fullServiceName, "interface",
                                         ServicePath, intReturned));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Int64MethodCall(&bus, sessionId);
                    }
                } else {
                    const int16_t intReturned = 0;
                    if (AJ_UnmarshalArgs(&msg, "x", &intReturned) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%llu)\n", msg.error, intReturned));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Struct"));
                StructMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Struct */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_STRUCT_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    struct SampleStruct structData;
                    status = AJ_UnmarshalArgs(&msg, "(yiudbsqnxt)", &structData.byte, &structData.int32, &structData.uint32,
                                              &structData.doubleValue, &structData.boolValue, &structData.stringValue, &structData.uint16,
                                              &structData.int16, &structData.int64, &structData.uint64);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%d'.\n", fullServiceName, "interface",
                                         ServicePath, structData.int32));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        StructMethodCall(&bus, sessionId);
                    }
                } else {
                    struct SampleStruct structData;
                    if (AJ_UnmarshalArgs(&msg, "(yiudbsqnxt)", &structData.byte, &structData.int32, &structData.uint32,
                                         &structData.doubleValue, &structData.boolValue, &structData.stringValue, &structData.uint16,
                                         &structData.int16, &structData.int64, &structData.uint64) == AJ_OK) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%lld'.\n", fullServiceName, "interface",
                                         ServicePath, structData.int32));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Dictionary"));
                DictionaryMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Dictionary */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_DICT_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    unsigned int key;
                    unsigned int value;
                    AJ_Arg array;
                    status = AJ_UnmarshalContainer(&msg, &array, AJ_ARG_ARRAY);
                    status = AJ_UnmarshalArgs(&msg, "{uv}", &key, "u", &value);
                    status = AJ_UnmarshalCloseContainer(&msg, &array);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' ' %u'.\n", fullServiceName, "interface",
                                         ServicePath, key, value));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        StructMethodCall(&bus, sessionId);
                    }
                } else {
                    unsigned int key;
                    unsigned int value;
                    AJ_Arg array;
                    status = AJ_UnmarshalContainer(&msg, &array, AJ_ARG_ARRAY);

                    if (AJ_UnmarshalArgs(&msg, "{uv}", &key, "u", &value) == AJ_OK) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' ' %u'.\n", fullServiceName, "interface",
                                         ServicePath, key, value));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    AJ_UnmarshalCloseContainer(&msg, &array);
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Byte Array"));
                ByteArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Byte Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_BYTE_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t* array;
                    size_t size;
                    int i;
                    status = AJ_UnmarshalArgs(&msg, "ay", (const uint8_t**)&array, &size);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));
                        for (i = 1; i < size; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %u'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        ByteArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    uint8_t* array;
                    size_t size;
                    if (AJ_UnmarshalArgs(&msg, "ay", (const uint8_t**)&array, &size) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Int Array"));
                IntArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Int Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_INT_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    int32_t array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "i", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%d'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));

                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %d'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        IntArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    int* array;
                    size_t size;
                    if (AJ_UnmarshalArgs(&msg, "ai", (const int**)&array, &size) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Unsigned Int Array"));
                UnsignedIntArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Unsigned Int Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_UINT_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    unsigned int array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "u", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));

                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %u'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        UnsignedIntArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    unsigned int* array;
                    size_t size;
                    if (AJ_UnmarshalArgs(&msg, "au", (const unsigned int**)&array, &size) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%u)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Int Array"));
                DoubleArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Double Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_DOUBLE_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    double array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "d", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);


                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%f'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));

                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %f'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        DoubleArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    double array [5];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "d", &array[0]) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Bool Array"));
                BoolArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Bool Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_BOOL_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    bool array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "b", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);


                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%s'.\n", fullServiceName, "interface",
                                         ServicePath, array[0] ? "true" : "false"));
                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %s'.\n", i, array[i] ? "true" : "false"));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        DoubleArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    bool array [5];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "b", &array[0]) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "String Array"));
                StringArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*String Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_STRING_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    char* array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "s", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);


                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%s'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));
                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %s'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        StringArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    char* array [5];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "s", &array[0]) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call  %s \n", "Unsigned Int 16 Array"));
                UnsignedInt16ArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Unsigned Int 16 Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_UINT16_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    uint16_t array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "q", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);


                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));
                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %u'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        UnsignedInt16ArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    uint16_t array [5];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "q", &array[0]) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Int 16 Array"));
                Int16ArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Int 16 Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_INT16_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    int16_t array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "n", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);


                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%d'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));
                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %d'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Int16ArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    int16_t array [5];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "n", &array[0]) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Unsigned Int 64 Array"));
                UnsignedInt64ArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Unsigned Int 16 Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_UINT64_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    uint64_t array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "t", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);


                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));
                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %u'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        UnsignedInt64ArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    uint64_t array [5];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "t", &array[0]) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Int 64 Array"));
                Int64ArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Int 64 Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_INT64_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 5;
                    int64_t array [5];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "x", &array[size]);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);


                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%d'.\n", fullServiceName, "interface",
                                         ServicePath, array[0]));
                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' %d'.\n", i, array[i]));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Int64ArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    int64_t array [5];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "n", &array[0]) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Struct Array"));
                StructArrayMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Int 64 Array*/
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_STRUCT_ARRAY_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    int arrayLength = 3;
                    struct ArrayStruct array [3];
                    size_t size = 0;
                    AJ_Arg arg1;
                    int i;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);

                    while (status == AJ_OK || (size < arrayLength)) {
                        status = AJ_UnmarshalArgs(&msg, "(is)", &array[size].intVar, &array[size].stringValue);
                        size++;
                    }
                    /*
                     * We expect AJ_ERR_NO_MORE
                     */
                    if (status == AJ_ERR_NO_MORE) {
                        status = AJ_OK;
                    }

                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%d'  '%s'.\n", fullServiceName, "interface",
                                         ServicePath, array[0].intVar, array[0].stringValue));
                        for (i = 1; i < arrayLength; i++) {
                            AJ_AlwaysPrintf(("Value '%d' '%d' '%s' .\n", i, array[i].intVar, array[i].stringValue));
                        }
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        StructArrayMethodCall(&bus, sessionId);
                    }
                } else {
                    struct ArrayStruct array [3];
                    AJ_Arg arg1;

                    status = AJ_UnmarshalContainer(&msg, &arg1, AJ_ARG_ARRAY);
                    if (AJ_UnmarshalArgs(&msg, "(is)", &array[0].intVar, &array[0].stringValue) == AJ_OK) {
                        AJ_AlwaysPrintf(("Method call returned error %s (%f)\n", msg.error, array[0]));
                    } else {
                        AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                    }
                    status = AJ_UnmarshalCloseContainer(&msg, &arg1);
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Nested Struct Array"));
                NestedStructMethodCall(&bus, sessionId);
                break;

            /***********************************************************************************************/
            /*Nested Struct */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_SERVICE_NESTED_STRUCT_CLIENT):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    int intVal;
                    unsigned int uIntVal;
                    status = AJ_UnmarshalArgs(&msg, "(y(iu))", &byte, &intVal, &uIntVal);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %d' '%u'.\n", fullServiceName, "interface",
                                         ServicePath, byte, intVal, uIntVal));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        NestedStructMethodCall(&bus, sessionId);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                if (padding) {
                    AJ_AlwaysPrintf(("Method call %s \n", "Padding 1"));
                    Padding1MethodCall(&bus, sessionId, &paddingStruct);
                    break;
                } else {
                    done = TRUE;
                    break;
                }

            /***********************************************************************************************/
            /*Padding 1 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_1):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(yqut)", &byte, &uint16Val, &uint32Val, &uint64Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %u' '%u' '%llu'.\n", fullServiceName, "padding",
                                         ServicePath, byte, uint16Val, uint32Val, uint64Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding1MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 2"));
                Padding2MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 2 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_2):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(yqtu)", &byte, &uint16Val, &uint64Val, &uint32Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %u' '%llu' '%u'.\n", fullServiceName, "padding",
                                         ServicePath, byte, uint16Val, uint64Val, uint32Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding2MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 3"));
                Padding3MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 3 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_3):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(yuqt)", &byte, &uint32Val, &uint16Val, &uint64Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %u' '%u' '%llu'.\n", fullServiceName, "padding",
                                         ServicePath, byte, uint32Val, uint16Val, uint64Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding3MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 4"));
                Padding4MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 4 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_4):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(yutq)", &byte, &uint32Val, &uint64Val, &uint16Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %u' '%llu' '%u'.\n", fullServiceName, "padding",
                                         ServicePath,  byte, uint32Val, uint64Val, uint16Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding4MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 5"));
                Padding5MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 5 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_5):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(ytqu)", &byte, &uint64Val, &uint16Val, &uint32Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %llu' '%u' '%u'.\n", fullServiceName, "padding",
                                         ServicePath, byte, uint64Val, uint16Val, uint32Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding5MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 6"));
                Padding6MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 6 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_6):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(ytuq)", &byte, &uint64Val, &uint32Val, &uint16Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %llu' '%u' '%u'.\n", fullServiceName, "padding",
                                         ServicePath, byte, uint64Val, uint32Val, uint16Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding6MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 7"));
                Padding7MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 7 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_7):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(qyut)", &uint16Val, &byte, &uint32Val, &uint64Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %u' '%u' '%llu'.\n", fullServiceName, "padding",
                                         ServicePath, uint16Val, byte, uint32Val, uint64Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding7MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 8"));
                Padding8MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 8 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_8):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(qytu)", &uint16Val, &byte, &uint64Val, &uint32Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %u' '%llu' '%u'.\n", fullServiceName, "padding",
                                         ServicePath, uint16Val, byte, uint64Val, uint32Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding8MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 9"));
                Padding9MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 9 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_9):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(uyqt)", &uint32Val, &byte, &uint16Val, &uint64Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%u' %u' '%u' '%llu'.\n", fullServiceName, "padding",
                                         ServicePath, uint32Val, byte, uint16Val, uint64Val));
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding9MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                AJ_AlwaysPrintf(("Method call %s \n", "Padding 10"));
                Padding10MethodCall(&bus, sessionId, &paddingStruct);
                break;

            /***********************************************************************************************/
            /*Padding 10 */
            /***********************************************************************************************/
            case AJ_REPLY_ID(BASIC_CLIENT_PADDING_10):
                if (msg.hdr->msgType == AJ_MSG_METHOD_RET) {
                    uint8_t byte;
                    uint16_t uint16Val;
                    uint32_t uint32Val;
                    uint64_t uint64Val;
                    status = AJ_UnmarshalArgs(&msg, "(tyqu)", &uint64Val, &byte, &uint16Val, &uint32Val);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%llu' '%u' '%u' '%u'.\n", fullServiceName, "padding",
                                         ServicePath, uint64Val, byte, uint16Val, uint32Val));
                        done = TRUE;
                    } else {
                        AJ_InfoPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        Padding10MethodCall(&bus, sessionId, &paddingStruct);
                    }
                } else {
                    AJ_AlwaysPrintf(("Method call returned error %s\n", msg.error));
                }
                done = TRUE;
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /* A session was lost so return error to force a disconnect. */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u\n", id, reason));
                }
                status = AJ_ERR_SESSION_LOST;
                break;

            default:
                /* Pass to the built-in handlers. */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }

        /* Messages MUST be discarded to free resources. */
        AJ_CloseMsg(&msg);
    }

    if (status == AJ_ERR_SESSION_LOST) {
        AJ_AlwaysPrintf(("AllJoyn disconnect.\n"));
        AJ_Disconnect(&bus);
        exit(0);
    }
    AJ_AlwaysPrintf(("Basic client exiting with status %d.\n", status));

    return status;
}
int AJ_ServiceMain(void) {
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;

    /* One time initialization before calling any other AllJoyn APIs. */
    AJ_Initialize();

    /* This is for debug purposes and is optional. */
    AJ_PrintXML(AppObjects);

    AJ_RegisterObjects(AppObjects, NULL);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartService(&bus,
                                     NULL,
                                     CONNECT_TIMEOUT,
                                     FALSE,
                                     ServicePort,
                                     ServiceName,
                                     AJ_NAME_REQ_DO_NOT_QUEUE,
                                     NULL);

            if (status == AJ_OK) {
                AJ_InfoPrintf(("StartService returned %d, session_id=%u\n", status, sessionId));
                connected = TRUE;
            } else {
                continue;
            }
        }

        //if (AJ_OK == status) {
        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        //}

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    status = AJ_BusReplyAcceptSession(&msg, TRUE);
                    AJ_InfoPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
                    AJ_AlwaysPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
                }
                break;

            case BASIC_SERVICE_BYTE:
                status = AppHandleByte(&msg);
                break;

            case BASIC_SERVICE_INT:
                status = AppHandleInt(&msg);
                break;

            case BASIC_SERVICE_UNSIGNED_INT:
                status = AppHandleUnsignedInt(&msg);
                break;

            case BASIC_SERVICE_DOUBLE:
                status = AppHandleDouble(&msg);
                break;

            case BASIC_SERVICE_BOOL:
                status = AppHandleBoolean(&msg);
                break;

            case BASIC_SERVICE_STRING:
                status = AppHandleString(&msg);
                break;

            case BASIC_SERVICE_UINT16:
                status = AppHandleUInt16(&msg);
                break;

            case BASIC_SERVICE_INT16:
                status = AppHandleInt16(&msg);
                break;

            case BASIC_SERVICE_UINT64:
                status = AppHandleUInt64(&msg);
                break;

            case BASIC_SERVICE_INT64:
                status = AppHandleInt64(&msg);
                break;

            case BASIC_SERVICE_STRUCT:
                status = AppHandleStruct(&msg);
                break;

            case BASIC_SERVICE_DICT:
                status = AppHandleDictionary(&msg);
                break;

            case BASIC_SERVICE_BYTE_ARRAY:
                status = AppHandleByteArray(&msg);
                break;

            case BASIC_SERVICE_INT_ARRAY:
                status = AppHandleIntArray(&msg);
                break;

            case BASIC_SERVICE_UINT_ARRAY:
                status = AppHandleUnsignedIntArray(&msg);
                break;

            case BASIC_SERVICE_DOUBLE_ARRAY:
                status = AppHandleDoubleArray(&msg);
                break;

            case BASIC_SERVICE_BOOL_ARRAY:
                status = AppHandleBoolArray(&msg);
                break;

            case BASIC_SERVICE_STRING_ARRAY:
                status = AppHandleStringArray(&msg);
                break;

            case BASIC_SERVICE_UINT16_ARRAY:
                status = AppHandleUnsignedInt16Array(&msg);
                break;

            case BASIC_SERVICE_INT16_ARRAY:
                status = AppHandleInt16Array(&msg);
                break;

            case BASIC_SERVICE_UINT64_ARRAY:
                status = AppHandleUnsignedInt64Array(&msg);
                break;

            case BASIC_SERVICE_INT64_ARRAY:
                status = AppHandleInt64Array(&msg);
                break;

            case BASIC_SERVICE_STRUCT_ARRAY:
                status = AppHandleStructArray(&msg);
                break;

            case BASIC_SERVICE_NESTED_STRUCT:
                status = AppHandleNestedStruct(&msg);
                break;

            case BASIC_SERVICE_PADDING_1:
                status = AppHandlePadding1(&msg);
                break;

            case BASIC_SERVICE_PADDING_2:
                status = AppHandlePadding2(&msg);
                break;

            case BASIC_SERVICE_PADDING_3:
                status = AppHandlePadding3(&msg);
                break;

            case BASIC_SERVICE_PADDING_4:
                status = AppHandlePadding4(&msg);
                break;

            case BASIC_SERVICE_PADDING_5:
                status = AppHandlePadding5(&msg);
                break;

            case BASIC_SERVICE_PADDING_6:
                status = AppHandlePadding6(&msg);
                break;

            case BASIC_SERVICE_PADDING_7:
                status = AppHandlePadding7(&msg);
                break;

            case BASIC_SERVICE_PADDING_8:
                status = AppHandlePadding8(&msg);
                break;

            case BASIC_SERVICE_PADDING_9:
                status = AppHandlePadding9(&msg);
                break;

            case BASIC_SERVICE_PADDING_10:
                status = AppHandlePadding10(&msg);
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u\n", id, reason));
                }
                break;

            default:
                /* Pass to the built-in handlers. */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }

        /* Messages MUST be discarded to free resources. */
        AJ_CloseMsg(&msg);

        if (status == AJ_ERR_READ) {
            AJ_AlwaysPrintf(("AllJoyn disconnect.\n"));
            AJ_Disconnect(&bus);
            connected = FALSE;

            /* Sleep a little while before trying to reconnect. */
            AJ_Sleep(SLEEP_TIME);
        }
    }

    AJ_AlwaysPrintf(("Basic service exiting with status %d.\n", status));

    return status;
}

static void usage(void)
{
    printf("Usage: marshal_unmarshal_test [-h] [-s] [-c]\n\n");
    printf("Options:\n");
    printf("   -h   = Print this help message\n");
    printf("   -s   = Run the program as a service\n");
    printf("   -c   = Run the program as a client\n");
    printf("   -p   = Run padding tests\n");
    printf("\n");
}
#ifdef AJ_MAIN
int main(int argc, char** argv) {
    int16_t appType = 0;
    bool paddingTest = false;
    int i;

    /* Parse command line args */
    for (i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-c", argv[i])) {
            appType = 1;
        } else if (0 == strcmp("-s", argv[i])) {
            appType = 2;
        } else if (0 == strcmp("-p", argv[i])) {
            paddingTest = true;
        } else {
            AJ_AlwaysPrintf(("Unknown Option %s", argv[i]));
            usage();
            exit(1);
        }
    }

    if (appType == 2) {
        //#define AJ_MODULE BASIC_SERVICE
        return AJ_ServiceMain();
    } else {
        if (appType == 1) {
            //#define AJ_MODULE BASIC_CLIENT
            return AJ_ClientMain(paddingTest);
        } else {
            usage();
        }
        return 0;
    }

}

#endif
