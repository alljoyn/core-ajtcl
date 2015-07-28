/**
 * @file
 */
/******************************************************************************
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
#include <ajtcl/aj_target.h>

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_crypto_sha2.h>
#include <ajtcl/aj_debug.h>

int AJ_Main(void);

typedef struct {
    const char* msg;     /* input message - ascii */
    const char* dig;     /* output digest - hex string */
} TEST_SHA;

static TEST_SHA sha256test[] = {
    {
        "abc",
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
    },
};

typedef struct {
    const char* key;      /* input key (for hmac) - hex string */
    const char* seed;     /* input message - ascii */
    const char* expected; /* output digest - hex string */
} TEST_PRF;

static TEST_PRF prftest[] = {
    {
        /* Shortest allowable key is 24 bytes */
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "Hi There",
        "0AB50319EFE5E73DF3327DCE552DBF1C4EF6EC0C4192230057B5194E6C277609"
        "A453979FD1D25F922DF3A2D296599CECB3ED0FED975C8CBBD9E791B354C744C1"
        "B09C5C7F586071CFB5EA25F20450E330DB2FB305FF812DFD8FC987F8EFACE01D"
        "65DB64DF21DD6C194D3BAFE6AECBE791A8263B1E59E877B96EB7C4961DB3DC6A"
        "058CE104B96D321783728BBE8EB9DB49EC20098A0BB1CF12E6D4D60B26776576"
        "EA0FFA170040EA1CA79E25701D976A5C3F43EF28AB6606F2E807EB4BF193604C"
        "BF450C7CDCEE536D"
    },
    {
        "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
        "what do ya want for nothing?",
        "62C00DD5EB0752876B03B235BCDA99F3D3922650606760A89CDCDDC7BBF7A2B1"
        "9321586328DFECCAFD43919EA5FA44967DFAE9B69D90AF00CC417C647CACB5CD"
        "5D6FB8288781C2176FC32F85B663ACC30EF0C425FC8A19746093D0CAEC2289C7"
        "288652EF213FD670FC629424D38FEF486287DC505C47E38890E0565F9437DAA3"
        "129136E24A745F4DA00B40107E0FE9F94C754D02A081D29C72441CC229EEDC13"
        "A0D297CA86F2C479E485575D5264AE15212A24FC93C278E6AB10B45BED28F3D2"
        "67A2A18D5735F40E"
    },
    {
        /* Longest allowable key is 128 bytes */
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "707F5855E679CF2B8647D83E1F5B5C50CC7841C47F84F962F69250480C50FEC0"
        "69D2F8D92D35ECAE7F893F7A959FF837104750C6C8887873D8D5800DFE134426"
        "AEE5DD6A109AD8B74038AA134C712E8C9B573BDF01AA572A4AA44A5F412087EF"
        "B756770F9F136092F04B7380FBB30F6442088CFB9A9727471A26DA441F90A894"
        "7EA7E12C02485B57B5A1BA5C63046387CA2A41FB2C7103FCF2863A1271B4CE81"
        "FFB4007CC3203DDB465F0664562974094BDD288A013B372F2388070B446D8465"
        "45AD2309776A7B65"
    },
    {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "This is a test using a larger than block-size key and a larger t"
        "han block-size data. The key needs to be hashed before being use"
        "d by the HMAC algorithm.",
        "956BBE25A75C5A30F88FA7A7CECEDC04124C1FFE3AE172758D73757A4A442708"
        "DCEBC685BCDD6F28DF7422F3F99D2087F477E954FC8CADF54476522CE439700A"
        "267E7AAC6615D90F0DACFB5FAAD582C6BFD4A326BAFD75C40DB615274EB40710"
        "08656461BAC11FEFDBC4B4E1BBFAF62D9423ADD1E66196C7DDF9430BAA56D5A0"
        "5A6ECD43922F8B982F98C3A41CA46C7122F4AD34F34EA42F471D453F61FEF6F6"
        "B47B1E06F8A5C8B7573C4D1A370EF540B3BC82D3056F5E308945E7F7019AABCE"
        "E9BBA1A576D5C2F1"
    },
};

int AJ_Main(void)
{
    uint32_t i;
    AJ_Status status;

    AJ_AlwaysPrintf(("SHA256 unit test START\n"));
    for (i = 0; i < ArraySize(sha256test); i++) {
        AJ_SHA256_Context* ctx;
        const uint8_t* msg;
        const char* expected;
        uint32_t mlen;
        uint8_t digBuf[AJ_SHA256_DIGEST_LENGTH];
        char digStr[AJ_SHA256_DIGEST_LENGTH * 2 + 1];

        memset(&ctx, 0, sizeof(ctx));
        msg = (const uint8_t*) sha256test[i].msg;
        expected = sha256test[i].dig;
        mlen = (uint32_t)strlen((char*)msg);

        ctx = AJ_SHA256_Init();
        AJ_SHA256_Update(ctx, msg, mlen);
        status = AJ_SHA256_Final(ctx, digBuf);
        if (AJ_OK != status) {
            AJ_AlwaysPrintf(("SHA final failure for test #%u\n", i));
            goto ErrorExit;
        }

        AJ_RawToHex(digBuf, AJ_SHA256_DIGEST_LENGTH, digStr, AJ_SHA256_DIGEST_LENGTH * 2 + 1, 0);
        if (strcmp(expected, digStr) != 0) {
            AJ_AlwaysPrintf(("SHA verification failure for test #%u\nexpected: %s\nactual: %s\n", i, expected, digStr));
            goto ErrorExit;
        }
        AJ_AlwaysPrintf(("Passed and verified SHA test #%u\n", i));
    }
    AJ_AlwaysPrintf(("SHA256 unit test PASSED\n"));

    AJ_AlwaysPrintf(("PRF unit test START\n"));
    for (i = 0; i < ArraySize(prftest); i++) {
        const char* expected;
        uint8_t key[128];
        uint8_t randBuf[200];
        char randStr[200 * 2 + 1];
        const uint8_t* inputs[4];
        uint8_t lengths[4];

        expected = prftest[i].expected;

        AJ_HexToRaw(prftest[i].key, 0, key, sizeof(key));

        inputs[0] = key;
        inputs[1] = inputs[2] = inputs[3] = (uint8_t*)prftest[i].seed;

        lengths[0] = strlen((char*)prftest[i].key) / 2;
        lengths[1] = lengths[2] = lengths[3] = (uint8_t)strlen((char*)inputs[1]);

        AJ_Crypto_PRF_SHA256(inputs, lengths, 4, randBuf, sizeof(randBuf));

        AJ_RawToHex(randBuf, sizeof(randBuf), randStr, sizeof(randStr), 0);
        if (strcmp(expected, randStr) != 0) {
            AJ_AlwaysPrintf(("PRF verification failure for test #%u\nexpected: %s\nactual: %s\n", i, expected, randStr));
            goto ErrorExit;
        }
        AJ_AlwaysPrintf(("Passed and verified PRF test #%u\n", i));
    }
    AJ_AlwaysPrintf(("PRF unit test PASSED\n"));

    return 0;

ErrorExit:

    AJ_AlwaysPrintf(("Crypto unit test FAILED\n"));
    return 1;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
