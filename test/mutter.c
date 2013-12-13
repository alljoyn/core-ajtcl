/**
 * @file  Marhal/Unmarshal Tester
 */
/******************************************************************************
 * Copyright (c) 2012-2013, AllSeen Alliance. All rights reserved.
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

#include "alljoyn.h"
#include "aj_util.h"
#include "aj_debug.h"
#include "aj_bufio.h"

static uint8_t wireBuffer[8 * 1024];
static size_t wireBytes = 0;

static uint8_t txBuffer[1024];
static uint8_t rxBuffer[1024];

static AJ_Status TxFunc(AJ_IOBuffer* buf)
{
    size_t tx = AJ_IO_BUF_AVAIL(buf);;


    if ((wireBytes + tx) > sizeof(wireBuffer)) {
        return AJ_ERR_WRITE;
    } else {
        memcpy(wireBuffer + wireBytes, buf->bufStart, tx);
        AJ_IO_BUF_RESET(buf);
        wireBytes += tx;
        return AJ_OK;
    }
}

AJ_Status RxFunc(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    size_t rx = AJ_IO_BUF_SPACE(buf);

    rx = min(len, rx);
    rx = min(wireBytes, rx);
    if (!rx) {
        return AJ_ERR_READ;
    } else {
        memcpy(buf->writePtr, wireBuffer, rx);
        /*
         * Shuffle the remaining data to the front of the buffer
         */
        memmove(wireBuffer, wireBuffer + rx, wireBytes - rx);
        wireBytes -= rx;
        buf->writePtr += rx;
        return AJ_OK;
    }
}

static const char* const testSignature[] = {
    "a{us}",
    "u(usu(ii)qsq)yyy",
    "a(usay)",
    "aas",
    "ivi",
    "v",
    "v",
    "(vvvvvv)",
    "uqay",
    "a(uuuu)",
    "a(sss)",
    "ya{ss}",
    "yyyyya{ys}",
    "(iay)",
    "ia{iv}i"
};

typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} TestStruct;

#ifndef NDEBUG
static AJ_Status MsgInit(AJ_Message* msg, uint32_t msgId, uint8_t msgType)
{
    msg->objPath = "/test/mutter";
    msg->iface = "test.mutter";
    msg->member = "mumble";
    msg->msgId = msgId;
    msg->signature = testSignature[msgId];
    return AJ_OK;
}

extern AJ_MutterHook MutterHook;
#endif


static const char* const Fruits[] = {
    "apple", "banana", "cherry", "durian", "elderberry", "fig", "grape"
};

static const char* const Colors[] = {
    "azure", "blue", "cyan", "dun", "ecru"
};

static const uint8_t Data8[] = { 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xA1, 0xB1, 0xC2, 0xD3 };
static const uint16_t Data16[] = { 0xFF01, 0xFF02, 0xFF03, 0xFF04, 0xFF05, 0xFF06 };

#define CHECK(x) if ((status = (x)) != AJ_OK) { break; }

int AJ_Main()
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_Message txMsg;
    AJ_Message rxMsg;
    AJ_Arg arg;
    AJ_Arg array1;
    AJ_Arg array2;
    AJ_Arg struct1;
    AJ_Arg struct2;
    size_t sz;
    uint32_t i;
    uint32_t j;
    uint32_t k;
    uint32_t key;
    uint32_t len;
    uint32_t u;
    uint32_t v;
    int32_t n;
    int32_t m;
    uint16_t q;
    uint16_t r;
    uint8_t y;
    char* str;
    char* sig;
    void* raw;

    const size_t lengthOfShortGUID = 16;

    bus.sock.tx.direction = AJ_IO_BUF_TX;
    bus.sock.tx.bufSize = sizeof(txBuffer);
    bus.sock.tx.bufStart = txBuffer;
    bus.sock.tx.readPtr = bus.sock.tx.bufStart;
    bus.sock.tx.writePtr = bus.sock.tx.bufStart;
    bus.sock.tx.send = TxFunc;

    bus.sock.rx.direction = AJ_IO_BUF_RX;
    bus.sock.rx.bufSize = sizeof(rxBuffer);
    bus.sock.rx.bufStart = rxBuffer;
    bus.sock.rx.readPtr = bus.sock.rx.bufStart;
    bus.sock.rx.writePtr = bus.sock.rx.bufStart;
    bus.sock.rx.recv = RxFunc;

    /*
     * mutter doesn't connect to an actual daemon.
     * Hence, to ensure that we don't fail the header validation checks,
     * manually set the unique name of the Bus.
     */
    strncpy(bus.uniqueName, "DummyNaaaame.N1", lengthOfShortGUID);

    /*
     * Set the hook
     */
#ifndef NDEBUG
    MutterHook = MsgInit;
#else
    AJ_Printf("mutter only works in DEBUG builds\n");
    return -1;
#endif

    for (i = 0; i < ArraySize(testSignature); ++i) {

        status = AJ_MarshalSignal(&bus, &txMsg, i, "mutter.service", 0, 0, 0);
        if (status != AJ_OK) {
            break;
        }

        switch (i) {
        case 0:
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));
            for (key = 0; key < ArraySize(Fruits); ++key) {
                AJ_Arg dict;
                CHECK(AJ_MarshalContainer(&txMsg, &dict, AJ_ARG_DICT_ENTRY));
                CHECK(AJ_MarshalArgs(&txMsg, "us", key, Fruits[key]));
                CHECK(AJ_MarshalCloseContainer(&txMsg, &dict));
            }
            if (status == AJ_OK) {
                CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            }
            break;

        case 1:
            CHECK(AJ_MarshalArgs(&txMsg, "u", 11111));
            CHECK(AJ_MarshalContainer(&txMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_MarshalArgs(&txMsg, "usu", 22222, "hello", 33333));
#ifdef EXPANDED_FORM
            CHECK(AJ_MarshalContainer(&txMsg, &struct2, AJ_ARG_STRUCT));
            CHECK(AJ_MarshalArgs(&txMsg, "ii", -100, -200));
            CHECK(AJ_MarshalCloseContainer(&txMsg, &struct2));
#else
            CHECK(AJ_MarshalArgs(&txMsg, "(ii)", -100, -200));
#endif
            CHECK(AJ_MarshalArgs(&txMsg, "qsq", 4444, "goodbye", 5555));
            CHECK(AJ_MarshalCloseContainer(&txMsg, &struct1));
            CHECK(AJ_MarshalArgs(&txMsg, "yyy", 1, 2, 3));
            break;

        case 2:
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));
            for (u = 0; u < ArraySize(Fruits); ++u) {
#ifdef EXPANDED_FORM
                CHECK(AJ_MarshalContainer(&txMsg, &struct1, AJ_ARG_STRUCT));
                CHECK(AJ_MarshalArgs(&txMsg, "us", u, Fruits[u]));
                CHECK(AJ_MarshalArg(&txMsg, AJ_InitArg(&arg, AJ_ARG_BYTE, AJ_ARRAY_FLAG, Data8, u)));
                CHECK(AJ_MarshalCloseContainer(&txMsg, &struct1));
#else
                CHECK(AJ_MarshalArgs(&txMsg, "(usay)", u, Fruits[u], Data8, u));
#endif
            }
            if (status == AJ_OK) {
                CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            }
            break;

        case 3:
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));
            for (j = 0; j < 3; ++j) {
                CHECK(AJ_MarshalContainer(&txMsg, &array2, AJ_ARG_ARRAY));
                for (k = j; k < ArraySize(Fruits); ++k) {
                    CHECK(AJ_MarshalArgs(&txMsg, "s", Fruits[k]));
                }
                CHECK(AJ_MarshalCloseContainer(&txMsg, &array2));
            }
            if (status == AJ_OK) {
                CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            }
            break;

        case 4:
            CHECK(AJ_MarshalArgs(&txMsg, "i", 987654321));
            CHECK(AJ_MarshalVariant(&txMsg, "a(ii)"));
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));
            for (j = 0; j < 16; ++j) {
#ifdef EXPANDED_FORM
                CHECK(AJ_MarshalContainer(&txMsg, &struct1, AJ_ARG_STRUCT));
                CHECK(AJ_MarshalArgs(&txMsg, "ii", j + 1, (j + 1) * 100));
                CHECK(AJ_MarshalCloseContainer(&txMsg, &struct1));

#else
                CHECK(AJ_MarshalArgs(&txMsg, "(ii)", j + 1, (j + 1) * 100));
#endif
            }
            if (status == AJ_OK) {
                CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            }
            CHECK(AJ_MarshalArgs(&txMsg, "i", 123456789));
            break;

        case 5:
#ifdef EXPANDED_FORM
            CHECK(AJ_MarshalVariant(&txMsg, "(ivi)"));
            CHECK(AJ_MarshalContainer(&txMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_MarshalArgs(&txMsg, "i", 1212121));
            CHECK(AJ_MarshalVariant(&txMsg, "s"));
            CHECK(AJ_MarshalArgs(&txMsg, "s", "inner variant"));
            CHECK(AJ_MarshalArgs(&txMsg, "i", 3434343));
            CHECK(AJ_MarshalCloseContainer(&txMsg, &struct1));
#else
            CHECK(AJ_MarshalArgs(&txMsg, "v", "(ivi)", 121212121, "s", "inner variant", 3434343));
#endif
            break;

        case 6:
            CHECK(AJ_MarshalVariant(&txMsg, "v"));
            CHECK(AJ_MarshalVariant(&txMsg, "v"));
            CHECK(AJ_MarshalVariant(&txMsg, "v"));
            CHECK(AJ_MarshalVariant(&txMsg, "v"));
            CHECK(AJ_MarshalVariant(&txMsg, "s"));
            CHECK(AJ_MarshalArgs(&txMsg, "s", "deep variant"));
            break;

        case 7:
#ifdef EXPANDED_FORM
            CHECK(AJ_MarshalContainer(&txMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_MarshalVariant(&txMsg, "i"));
            CHECK(AJ_MarshalArgs(&txMsg, "i", 1212121));
            CHECK(AJ_MarshalVariant(&txMsg, "s"));
            CHECK(AJ_MarshalArgs(&txMsg, "s", "variant"));
            CHECK(AJ_MarshalVariant(&txMsg, "ay"));
            CHECK(AJ_MarshalArg(&txMsg, AJ_InitArg(&arg, AJ_ARG_BYTE, AJ_ARRAY_FLAG, Data8, sizeof(Data8))));
            CHECK(AJ_MarshalVariant(&txMsg, "ay"));
            CHECK(AJ_MarshalArg(&txMsg, AJ_InitArg(&arg, AJ_ARG_BYTE, AJ_ARRAY_FLAG, Data8, sizeof(Data8))));
            CHECK(AJ_MarshalVariant(&txMsg, "aq"));
            CHECK(AJ_MarshalArg(&txMsg, AJ_InitArg(&arg, AJ_ARG_UINT16, AJ_ARRAY_FLAG, Data16, sizeof(Data16))));
            CHECK(AJ_MarshalVariant(&txMsg, "s"));
            CHECK(AJ_MarshalArgs(&txMsg, "s", "variant2"));
            CHECK(AJ_MarshalCloseContainer(&txMsg, &struct1));
#else
            CHECK(AJ_MarshalArgs(&txMsg, "(vvvvvv)",
                                 "i", 121212121,
                                 "s", "variant",
                                 "ay",  Data8, sizeof(Data8),
                                 "ay",  Data8, sizeof(Data8),
                                 "aq",  Data16, sizeof(Data16),
                                 "s",  "variant2"));
#endif
            break;

        case 8:
            CHECK(AJ_MarshalArgs(&txMsg, "uq", 0xF00F00F0, 0x0707));
            len = 5000;
            CHECK(AJ_DeliverMsgPartial(&txMsg, len + 4));
            CHECK(AJ_MarshalRaw(&txMsg, &len, 4));
            for (j = 0; j < len; ++j) {
                uint8_t n = (uint8_t)j;
                CHECK(AJ_MarshalRaw(&txMsg, &n, 1));
            }
            break;

        case 9:
            len = 500;
            u = len * sizeof(TestStruct);
            CHECK(AJ_DeliverMsgPartial(&txMsg, u + sizeof(u) + 4));
            CHECK(AJ_MarshalRaw(&txMsg, &u, sizeof(u)));
            /*
             * Structs are always 8 byte aligned
             */
            u = 0;
            CHECK(AJ_MarshalRaw(&txMsg, &u, 4));
            for (j = 0; j < len; ++j) {
                TestStruct ts;
                ts.a = j;
                ts.b = j + 1;
                ts.c = j + 2;
                ts.d = j + 3;
                CHECK(AJ_MarshalRaw(&txMsg, &ts, sizeof(ts)));
            }
            break;

        case 10:
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));
            CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            break;

        case 11:
            CHECK(AJ_MarshalArgs(&txMsg, "y", 127));
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));
            for (key = 0; key < ArraySize(Colors); ++key) {
                AJ_Arg dict;
                CHECK(AJ_MarshalContainer(&txMsg, &dict, AJ_ARG_DICT_ENTRY));
                CHECK(AJ_MarshalArgs(&txMsg, "ss", Colors[key], Fruits[key]));
                CHECK(AJ_MarshalCloseContainer(&txMsg, &dict));
            }
            if (status == AJ_OK) {
                CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            }
            break;

        case 12:
            CHECK(AJ_MarshalArgs(&txMsg, "y", 0x11));
            CHECK(AJ_MarshalArgs(&txMsg, "y", 0x22));
            CHECK(AJ_MarshalArgs(&txMsg, "y", 0x33));
            CHECK(AJ_MarshalArgs(&txMsg, "y", 0x44));
            CHECK(AJ_MarshalArgs(&txMsg, "y", 0x55));
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));
            for (key = 0; key < ArraySize(Colors); ++key) {
                AJ_Arg dict;
                CHECK(AJ_MarshalContainer(&txMsg, &dict, AJ_ARG_DICT_ENTRY));
                CHECK(AJ_MarshalArgs(&txMsg, "ys", (uint8_t)key, Colors[key]));
                CHECK(AJ_MarshalCloseContainer(&txMsg, &dict));
            }
            if (status == AJ_OK) {
                CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            }
            break;

        case 13:
            CHECK(AJ_MarshalContainer(&txMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_MarshalArgs(&txMsg, "i", 3434343));
            CHECK(AJ_MarshalArg(&txMsg, AJ_InitArg(&arg, AJ_ARG_BYTE, AJ_ARRAY_FLAG, Data8, sizeof(Data8))));
            CHECK(AJ_MarshalCloseContainer(&txMsg, &struct1));
            break;

        case 14:
            CHECK(AJ_MarshalArgs(&txMsg, "i", 0x1111));
            CHECK(AJ_MarshalContainer(&txMsg, &array1, AJ_ARG_ARRAY));

            for (j = 0; j < 8; ++j) {
#ifdef EXPANDED_FORM
                AJ_Arg dict;
                CHECK(AJ_MarshalContainer(&txMsg, &dict, AJ_ARG_DICT_ENTRY));
                CHECK(AJ_MarshalArgs(&txMsg, "i", j));
                if (j == 4) {
                    CHECK(AJ_MarshalVariant(&txMsg, "s"));
                    CHECK(AJ_MarshalArgs(&txMsg, "s", "This is a variant string"));
                } else {
                    CHECK(AJ_MarshalVariant(&txMsg, "i"));
                    CHECK(AJ_MarshalArgs(&txMsg, "i", j + 200));
                }
                CHECK(AJ_MarshalCloseContainer(&txMsg, &dict));
#else
                if (j == 4) {
                    CHECK(AJ_MarshalArgs(&txMsg, "{iv}", j, "s", "This is a variant string"));
                } else {
                    CHECK(AJ_MarshalArgs(&txMsg, "{iv}", j, "i", j + 200));
                }
#endif
            }

            CHECK(AJ_MarshalCloseContainer(&txMsg, &array1));
            CHECK(AJ_MarshalArgs(&txMsg, "i", 0x2222));
            break;
        }
        if (status != AJ_OK) {
            AJ_Printf("Failed %d\n", i);
            break;
        }

        AJ_Printf("deliver\n");
        AJ_DeliverMsg(&txMsg);

        status = AJ_UnmarshalMsg(&bus, &rxMsg, 0);
        if (status != AJ_OK) {
            break;
        }

        switch (i) {
        case 0:
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            for (j = 0; j >= 0; ++j) {
                if (j & 1) {
                    AJ_Printf("Skipping dict entry %d\n", j);
                    CHECK(AJ_SkipArg(&rxMsg));
                } else {
                    char* fruit;
                    AJ_Arg dict;
                    CHECK(AJ_UnmarshalContainer(&rxMsg, &dict, AJ_ARG_DICT_ENTRY));
                    CHECK(AJ_UnmarshalArgs(&rxMsg, "us", &key, &fruit));
                    AJ_Printf("Unmarshal[%d] = %s\n", key, fruit);
                    CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &dict));
                }
            }
            /*
             * We expect AJ_ERR_NO_MORE
             */
            if (status == AJ_ERR_NO_MORE) {
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            }
            break;

        case 1:
            CHECK(AJ_UnmarshalArgs(&rxMsg, "u", &u));
            AJ_Printf("Unmarshal %u\n", u);
            CHECK(AJ_UnmarshalContainer(&rxMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "usu", &u, &str, &v));
            AJ_Printf("Unmarshal %u %s %u\n", u, str, v);
            CHECK(AJ_UnmarshalContainer(&rxMsg, &struct2, AJ_ARG_STRUCT));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "ii", &n, &m));
            AJ_Printf("Unmarshal %d %d\n", n, m);
            CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &struct2));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "qsq", &q, &str, &r));
            AJ_Printf("Unmarshal %u %s %u\n", q, str, r);
            CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &struct1));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            AJ_Printf("Unmarshal %d\n", y);
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            AJ_Printf("Unmarshal %d\n", y);
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            AJ_Printf("Unmarshal %d\n", y);
            break;

        case 2:
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            while (status == AJ_OK) {
#ifdef EXPANDED_FORM
                CHECK(AJ_UnmarshalContainer(&rxMsg, &struct1, AJ_ARG_STRUCT));
                CHECK(AJ_UnmarshalArgs(&rxMsg, "us", &u, &str));
                CHECK(AJ_UnmarshalArg(&rxMsg, &arg));
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &struct1));
#else
                size_t len;
                uint8_t* data;
                CHECK(AJ_UnmarshalArgs(&rxMsg, "(usay)", &u, &str, &data, &len));
#endif
                AJ_Printf("Unmarshal %d %s\n", u, str);
            }
            /*
             * We expect AJ_ERR_NO_MORE
             */
            if (status == AJ_ERR_NO_MORE) {
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            }
            break;

        case 3:
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            while (status == AJ_OK) {
                CHECK(AJ_UnmarshalContainer(&rxMsg, &array2, AJ_ARG_ARRAY));
                while (status == AJ_OK) {
                    CHECK(AJ_UnmarshalArg(&rxMsg, &arg));
                    AJ_Printf("Unmarshal %s\n", arg.val.v_string);
                }
                /*
                 * We expect AJ_ERR_NO_MORE
                 */
                if (status == AJ_ERR_NO_MORE) {
                    CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array2));
                }
            }
            /*
             * We expect AJ_ERR_NO_MORE
             */
            if (status == AJ_ERR_NO_MORE) {
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            }
            break;

        case 4:
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &j));
            AJ_Printf("Unmarshal %d\n", j);
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            while (status == AJ_OK) {
                CHECK(AJ_UnmarshalContainer(&rxMsg, &struct1, AJ_ARG_STRUCT));
                CHECK(AJ_UnmarshalArgs(&rxMsg, "ii", &j, &k));
                AJ_Printf("Unmarshal[%d] %d\n", j, k);
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &struct1));
            }
            /*
             * We expect AJ_ERR_NO_MORE
             */
            if (status != AJ_ERR_NO_MORE) {
                break;
            }
            CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &j));
            AJ_Printf("Unmarshal %d\n", j);
            break;

        case 5:
#ifdef EXPANDED_FORM
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalContainer(&rxMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &j));
            AJ_Printf("Unmarshal %d\n", j);
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalArgs(&rxMsg, "s", &str));
            AJ_Printf("Unmarshal %s\n", str);
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &j));
            AJ_Printf("Unmarshal %d\n", j);
            CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &struct1));
#else
            CHECK(AJ_UnmarshalArgs(&rxMsg, "v", "(ivi)", &j, "s", &str, &j));
#endif
            break;

        case 6:
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalArgs(&rxMsg, "s", &str));
            AJ_Printf("Unmarshal %s\n", str);
            break;

        case 7:
            CHECK(AJ_UnmarshalContainer(&rxMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &j));
            AJ_Printf("Unmarshal %d\n", j);
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalArgs(&rxMsg, "s", &str));
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalArg(&rxMsg, &arg));
            AJ_Printf("Skipping variant\n");
            CHECK(AJ_SkipArg(&rxMsg));
            CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
            AJ_Printf("Unmarshal variant %s\n", sig);
            CHECK(AJ_UnmarshalArg(&rxMsg, &arg));
            AJ_Printf("Skipping variant\n");
            CHECK(AJ_SkipArg(&rxMsg));
            CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &struct1));
            break;

        case 8:
            CHECK(AJ_UnmarshalArgs(&rxMsg, "uq", &j, &q));
            AJ_Printf("Unmarshal %x\n", j);
            AJ_Printf("Unmarshal %x\n", q);
            CHECK(AJ_UnmarshalRaw(&rxMsg, (const void**)&raw, sizeof(len), &sz));
            len = *((uint32_t*)raw);
            AJ_Printf("UnmarshalRaw %d\n", len);
            for (j = 0; j < len; ++j) {
                uint8_t v;
                CHECK(AJ_UnmarshalRaw(&rxMsg, (const void**)&raw, 1, &sz));
                v = *((uint8_t*)raw);
                if (v != (uint8_t)j) {
                    status = AJ_ERR_FAILURE;
                    break;
                }
            }
            break;

        case 9:
            CHECK(AJ_UnmarshalRaw(&rxMsg, (const void**)&raw, 4, &sz));
            len = *((uint32_t*)raw) / sizeof(TestStruct);
            /*
             * Structs are always 8 byte aligned
             */
            CHECK(AJ_UnmarshalRaw(&rxMsg, (const void**)&raw, 4, &sz));
            for (j = 0; j < len; ++j) {
                TestStruct* ts;
                CHECK(AJ_UnmarshalRaw(&rxMsg, (const void**)&ts, sizeof(TestStruct), &sz));
                if ((ts->a != j) || (ts->b != (j + 1)) || (ts->c != (j + 2)) || (ts->d != (j + 3))) {
                    status = AJ_ERR_FAILURE;
                    break;
                }
            }
            break;

        case 10:
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            status = AJ_UnmarshalArg(&rxMsg, &arg);
            /*
             * We expect AJ_ERR_NO_MORE
             */
            if (status == AJ_ERR_NO_MORE) {
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            }
            break;

        case 11:
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            while (TRUE) {
                AJ_Arg dict;
                char* fruit;
                char* color;
                CHECK(AJ_UnmarshalContainer(&rxMsg, &dict, AJ_ARG_DICT_ENTRY));
                CHECK(AJ_UnmarshalArgs(&rxMsg, "ss", &color, &fruit));
                AJ_Printf("Unmarshal[%s] = %s\n", color, fruit);
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &dict));
            }
            /*
             * We expect AJ_ERR_NO_MORE
             */
            if (status == AJ_ERR_NO_MORE) {
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            }
            break;

        case 12:
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "y", &y));
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            while (TRUE) {
                AJ_Arg dict;
                char* color;
#ifdef EXPANDED_FORM
                CHECK(AJ_UnmarshalContainer(&rxMsg, &dict, AJ_ARG_DICT_ENTRY));
                CHECK(AJ_UnmarshalArgs(&rxMsg, "ys", &y, &color));
                AJ_Printf("Unmarshal[%d] = %s\n", y, color);
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &dict));
#else
                CHECK(AJ_UnmarshalArgs(&rxMsg, "{ys}", &y, &color));
                AJ_Printf("Unmarshal[%d] = %s\n", y, color);
#endif
            }
            /*
             * We expect AJ_ERR_NO_MORE
             */
            if (status == AJ_ERR_NO_MORE) {
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            }
            break;

        case 13:
            CHECK(AJ_UnmarshalContainer(&rxMsg, &struct1, AJ_ARG_STRUCT));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &n));
            AJ_ASSERT(n == 3434343);

            CHECK(AJ_UnmarshalArg(&rxMsg, &arg));
            for (j = 0; j < arg.len; ++j) {
                uint8_t val = arg.val.v_byte[j];
                AJ_Printf("Unmarhsalled array1[%u] = %u\n", j, val);
                AJ_ASSERT(val == Data8[j]);
            }

            CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &struct1));
            break;

        case 14:
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &j));
            CHECK(AJ_UnmarshalContainer(&rxMsg, &array1, AJ_ARG_ARRAY));
            for (j = 0;; ++j) {
                AJ_Arg dict;
                int key;
                CHECK(AJ_UnmarshalContainer(&rxMsg, &dict, AJ_ARG_DICT_ENTRY));
                CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &key));
                if (key == 4) {
                    CHECK(AJ_UnmarshalVariant(&rxMsg, (const char**)&sig));
                    AJ_Printf("Unmarshal dict entry key=%d variant %s\n", key, sig);
                    CHECK(AJ_UnmarshalArgs(&rxMsg, sig, &str));
                } else {
                    AJ_Printf("Skipping dict entry key=%d\n", key);
                    CHECK(AJ_SkipArg(&rxMsg));
                }
                CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &dict));
            }
            CHECK(AJ_UnmarshalCloseContainer(&rxMsg, &array1));
            CHECK(AJ_UnmarshalArgs(&rxMsg, "i", &j));
            AJ_ASSERT(j == 0x2222);
            break;

        }

        if (status != AJ_OK) {
            AJ_Printf("Failed %d\n", i);
            break;
        }
        AJ_CloseMsg(&rxMsg);
        AJ_Printf("Passed %d\n", i);

    }
    if (status != AJ_OK) {
        AJ_Printf("Marshal/Unmarshal unit test[%d] failed %d\n", i, status);
    }

    return status;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif

