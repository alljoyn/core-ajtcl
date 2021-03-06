/**
 * @file
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
#include <ajtcl/aj_target.h>

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_debug.h>

#include "aestest_bigdata.h"

typedef struct {
    const char* key;     /* AES key */
    const char* nonce;   /* Nonce */
    uint8_t hdrLen;      /* Number of clear text bytes */
    const char* input;   /* Input text) */
    uint32_t repeat;     /* Number of times to repeat input */
    const char* output;  /* Authenticated and encrypted output for verification */
    uint8_t authLen;     /* Length of the authentication field */
} TEST_CASE;

/* Test vectors from RFC 3610 "Counter with CBC-MAC (CCM)", https://tools.ietf.org/html/rfc3610 */
static TEST_CASE const testVector[] = {
    {
        /* =============== RFC 3610 Packet Vector #1 ================== */
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000003020100A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        1,
        "0001020304050607588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0",
        8
    },
    {
        /* =============== RFC 3610 Packet Vector #2 ================== */
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000004030201A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        1,
        "000102030405060772C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916",
        8

    },
    {
        /*===============RFC3610PacketVector#3==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000005040302A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
        1,
        "000102030405060751B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA8596574ADAA76FBD9FB0C5",
        8
    },
    {
        /*===============RFC3610PacketVector#4==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000006050403A0A1A2A3A4A5",
        12,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        1,
        "000102030405060708090A0BA28C6865939A9A79FAAA5C4C2A9D4A91CDAC8C96C861B9C9E61EF1",
        8
    },
    {
        /*===============RFC3610PacketVector#5==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000007060504A0A1A2A3A4A5",
        12,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        1,
        "000102030405060708090A0BDCF1FB7B5D9E23FB9D4E131253658AD86EBDCA3E51E83F077D9C2D93",
        8
    },
    {
        /*===============RFC3610PacketVector#6==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000008070605A0A1A2A3A4A5",
        12,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
        1,
        "000102030405060708090A0B6FC1B011F006568B5171A42D953D469B2570A4BD87405A0443AC91CB94",
        8
    },
    {
        /*===============RFC3610PacketVector#7==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000009080706A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        1,
        "00010203040506070135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C048C56602C97ACBB7490",
        10
    },
    {
        /*===============RFC3610PacketVector#8==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "0000000A090807A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        1,
        "00010203040506077B75399AC0831DD2F0BBD75879A2FD8F6CAE6B6CD9B7DB24C17B4433F434963F34B4",
        10
    },
    {
        /*===============RFC3610PacketVector#9==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "0000000B0A0908A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
        1,
        "000102030405060782531A60CC24945A4B8279181AB5C84DF21CE7F9B73F42E197EA9C07E56B5EB17E5F4E",
        10
    },
    {
        /*===============RFC3610PacketVector#10==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "0000000C0B0A09A0A1A2A3A4A5",
        12,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        1,
        "000102030405060708090A0B07342594157785152B074098330ABB141B947B566AA9406B4D999988DD",
        10
    },
    {
        /*===============RFC3610PacketVector#11==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "0000000D0C0B0AA0A1A2A3A4A5",
        12,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        1,
        "000102030405060708090A0B676BB20380B0E301E8AB79590A396DA78B834934F53AA2E9107A8B6C022C",
        10
    },
    {
        /*===============RFC3610PacketVector#12==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "0000000E0D0C0BA0A1A2A3A4A5",
        12,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
        1,
        "000102030405060708090A0BC0FFA0D6F05BDB67F24D43A4338D2AA4BED7B20E43CD1AA31662E7AD65D6DB",
        10
    },
    {
        /*===============RFC3610PacketVector#13==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "00412B4EA9CDBE3C9696766CFA",
        8,
        "0BE1A88BACE018B108E8CF97D820EA258460E96AD9CF5289054D895CEAC47C",
        1,
        "0BE1A88BACE018B14CB97F86A2A4689A877947AB8091EF5386A6FFBDD080F8E78CF7CB0CDDD7B3",
        8
    },
    {
        /*===============RFC3610PacketVector#14==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "0033568EF7B2633C9696766CFA",
        8,
        "63018F76DC8A1BCB9020EA6F91BDD85AFA0039BA4BAFF9BFB79C7028949CD0EC",
        1,
        "63018F76DC8A1BCB4CCB1E7CA981BEFAA0726C55D378061298C85C92814ABC33C52EE81D7D77C08A",
        8
    },
    {
        /*===============RFC3610PacketVector#15==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "00103FE41336713C9696766CFA",
        8,
        "AA6CFA36CAE86B40B916E0EACC1C00D7DCEC68EC0B3BBB1A02DE8A2D1AA346132E",
        1,
        "AA6CFA36CAE86B40B1D23A2220DDC0AC900D9AA03C61FCF4A559A4417767089708A776796EDB723506",
        8
    },
    {
        /*===============RFC3610PacketVector#16==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "00764C63B8058E3C9696766CFA",
        12,
        "D0D0735C531E1BECF049C24412DAAC5630EFA5396F770CE1A66B21F7B2101C",
        1,
        "D0D0735C531E1BECF049C24414D253C3967B70609B7CBB7C499160283245269A6F49975BCADEAF",
        8
    },
    {
        /*===============RFC3610PacketVector#17==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "00F8B678094E3B3C9696766CFA",
        12,
        "77B60F011C03E1525899BCAEE88B6A46C78D63E52EB8C546EFB5DE6F75E9CC0D",
        1,
        "77B60F011C03E1525899BCAE5545FF1A085EE2EFBF52B2E04BEE1E2336C73E3F762C0C7744FE7E3C",
        8
    },
    {
        /*===============RFC3610PacketVector#18==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "00D560912D3F703C9696766CFA",
        12,
        "CD9044D2B71FDB8120EA60C06435ACBAFB11A82E2F071D7CA4A5EBD93A803BA87F",
        1,
        "CD9044D2B71FDB8120EA60C0009769ECABDF48625594C59251E6035722675E04C847099E5AE0704551",
        8
    },
    {
        /*===============RFC3610PacketVector#19==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "0042FFF8F1951C3C9696766CFA",
        8,
        "D85BC7E69F944FB88A19B950BCF71A018E5E6701C91787659809D67DBEDD18",
        1,
        "D85BC7E69F944FB8BC218DAA947427B6DB386A99AC1AEF23ADE0B52939CB6A637CF9BEC2408897C6BA",
        10
    },
    {
        /*===============RFC3610PacketVector#20==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "00920F40E56CDC3C9696766CFA",
        8,
        "74A0EBC9069F5B371761433C37C5A35FC1F39F406302EB907C6163BE38C98437",
        1,
        "74A0EBC9069F5B375810E6FD25874022E80361A478E3E9CF484AB04F447EFFF6F0A477CC2FC9BF548944",
        10
    },
    {
        /*===============RFC3610PacketVector#21==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "0027CA0C7120BC3C9696766CFA",
        8,
        "44A3AA3AAE6475CAA434A8E58500C6E41530538862D686EA9E81301B5AE4226BFA",
        1,
        "44A3AA3AAE6475CAF2BEED7BC5098E83FEB5B31608F8E29C38819A89C8E776F1544D4151A4ED3A8B87B9CE",
        10
    },
    {
        /*===============RFC3610PacketVector#22==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "005B8CCBCD9AF83C9696766CFA",
        12,
        "EC46BB63B02520C33C49FD70B96B49E21D621741632875DB7F6C9243D2D7C2",
        1,
        "EC46BB63B02520C33C49FD7031D750A09DA3ED7FDDD49A2032AABF17EC8EBF7D22C8088C666BE5C197",
        10
    },
    {
        /*===============RFC3610PacketVector#23==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "003EBE94044B9A3C9696766CFA",
        12,
        "47A65AC78B3D594227E85E71E2FCFBB880442C731BF95167C8FFD7895E337076",
        1,
        "47A65AC78B3D594227E85E71E882F1DBD38CE3EDA7C23F04DD65071EB41342ACDF7E00DCCEC7AE52987D",
        10
    },
    {
        /*===============RFC3610PacketVector#24==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "008D493B30AE8B3C9696766CFA",
        12,
        "6E37A6EF546D955D34AB6059ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4",
        1,
        "6E37A6EF546D955D34AB6059F32905B88A641B04B9C9FFB58CC390900F3DA12AB16DCE9E82EFA16DA62059",
        10
    },
    {
        /*===============Authenticationonly==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "008D493B30AE8B3C9696766CFA",
        33,
        "6E37A6EF546D955D34AB6059ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4",
        1,
        "6E37A6EF546D955D34AB6059ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4CA35DC8A1EBD6BC7EAD7",
        10
    },
    {
        /*===============Noheader==================*/
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "008D493B30AE8B3C9696766CFA",
        0,
        "6E37A6EF546D955D34AB6059ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4",
        1,
        "36ECBF5CDCF736D6080F6B4F54B03078C1D19CB2E0B18A3C3883AA48B3ABEE5A795300F8778A19BD45BC34",
        10
    },
    {
        /*===============16byteauthenticationfield==================*/
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000003020100A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        1,
        "0001020304050607588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384509DA654E32DEAC369C2DAE7133CB08D",
        16
    },
    {
        /* =============== Small payload ================== */
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000003020100A0A1A2A3A4A5",
        8,
        "000102030405060708090A0B0C0D",
        1,
        "0001020304050607588C979A61C6B7C00BB077809CAE",
        8
    },
    {
        /* =============== Small payload ================== */
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000003020100A0A1A2A3A4A5",
        1,
        "000102030405060708090A0B0C0D0E0F1011",
        1,
        "0051879E9568CD6AD5E97DC9DDD9E29087643EB868CBF8E0E0CC",
        8
    },
    {
        /* =============== Minimal header and payload ================== */
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
        "00000003020100A0A1A2A3A4A5",
        1,
        "0001",
        1,
        "0051C0EED548220130D4",
        8
    },
    {
        /* =============== Big Data ================== */
        "D7828D13B2B0BDC325A76236DF93CC6B",
        "008D493B30AE8B3C9696766CFA",
        42,
        "0BF89E3B7DB8624B5A7DEC72FD5A32369A6B84FE05D74A115E4D40A9055C6C0AD65609BEEFF93DBACCA5506AF7766196950671DEF6C70A7114225F1535BB8D",
        1040,
        expectedBigData,
        10
    }
};

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    uint32_t i;

    AJ_AlwaysPrintf(("AES CCM unit test start\n"));

    for (i = 0; i < ArraySize(testVector); i++) {

        uint8_t key[16];
        uint8_t input[64];
        uint8_t* msg;
        uint8_t nonce[16];
        uint32_t nlen = (uint32_t)strlen(testVector[i].nonce) / 2;
        uint32_t ilen = (uint32_t)strlen(testVector[i].input) / 2;
        uint32_t mlen = ilen * testVector[i].repeat;
        uint32_t j;
        char* out;
        size_t olen;

        AJ_HexToRaw(testVector[i].key, 0, key, sizeof(key));
        AJ_HexToRaw(testVector[i].nonce, 0, nonce, nlen);
        AJ_HexToRaw(testVector[i].input, 0, input, mlen);

        msg = AJ_Malloc(mlen + testVector[i].authLen);
        if (!msg) {
            AJ_AlwaysPrintf(("Allocation failed for test #%zu\n", i));
            goto ErrorExit;
        }
        for (j = 0; j < testVector[i].repeat; j++) {
            memcpy(&msg[ilen * j], &input[0], ilen);
        }

        olen = 2 * (mlen + testVector[i].authLen) + 1;
        out = AJ_Malloc(olen);
        if (!out) {
            AJ_AlwaysPrintf(("Allocation failed for test #%zu\n", i));
            goto ErrorExit;
        }

        status = AJ_Encrypt_CCM(key, msg, mlen, testVector[i].hdrLen, testVector[i].authLen, nonce, nlen);
        if (status != AJ_OK) {
            AJ_AlwaysPrintf(("Encryption failed (%d) for test #%u\n", status, i));
            goto ErrorExit;
        }
        AJ_RawToHex(msg, mlen + testVector[i].authLen, out, olen, FALSE);
        if (strcmp(out, testVector[i].output) != 0) {
            AJ_AlwaysPrintf(("Encrypt verification failure for test #%u\n%s\n", i, out));
            goto ErrorExit;
        }
        /*
         * Verify decryption.
         */
        status = AJ_Decrypt_CCM(key, msg, mlen, testVector[i].hdrLen, testVector[i].authLen, nonce, nlen);
        if (status != AJ_OK) {
            AJ_AlwaysPrintf(("Authentication failure (%d) for test #%u\n", status, i));
            goto ErrorExit;
        }
        AJ_RawToHex(msg, mlen, out, olen, FALSE);
        for (j = 0; j < testVector[i].repeat; j++) {
            if (strncmp(&out[2 * ilen * j], testVector[i].input, ilen * 2) != 0) {
                AJ_AlwaysPrintf(("Decrypt verification failure for test #%u\n%s\n", i, out));
                goto ErrorExit;
            }
        }
        AJ_AlwaysPrintf(("Passed and verified test #%zu\n", i));
        AJ_Free(msg);
        AJ_Free(out);
    }

    AJ_AlwaysPrintf(("AES CCM unit test PASSED\n"));

    return 0;

ErrorExit:

    AJ_AlwaysPrintf(("AES CCM unit test FAILED\n"));
    return 1;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif