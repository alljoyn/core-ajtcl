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
#define AJ_MODULE NVT

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_util.h>

uint8_t dbgNVT = 0;

AJ_Status TestNVRAM();
AJ_Status TestCreds();
extern void AJ_NVRAM_Layout_Print();

static uint16_t tid1 = 15;
static uint16_t tid2 = 16;
static uint16_t tid3 = 17;
static uint16_t tid4 = 18;

static uint16_t count = 0;

#define AJ_NVRAM_REQUESTED AJ_NVRAM_SIZE
#define RAND_DATA
#define READABLE_LOG

typedef enum _AJOBS_AuthType_Test {
    AJOBS_AUTH_TYPE_MIN_OF_WIFI_AUTH_TYPE = -4,
    AJOBS_AUTH_TYPE_WPA2_AUTO = -3,
    AJOBS_AUTH_TYPE_WPA_AUTO = -2,
    AJOBS_AUTH_TYPE_ANY = -1,
    AJOBS_AUTH_TYPE_OPEN = 0,
    AJOBS_AUTH_TYPE_WEP = 1,
    AJOBS_AUTH_TYPE_WPA_TKIP = 2,
    AJOBS_AUTH_TYPE_WPA_CCMP = 3,
    AJOBS_AUTH_TYPE_WPA2_TKIP = 4,
    AJOBS_AUTH_TYPE_WPA2_CCMP = 5,
    AJOBS_AUTH_TYPE_WPS = 6,
    AJOBS_AUTH_TYPE_MAX_OF_WIFI_AUTH_TYPE = 7
} AJOBS_AuthType_Test;

typedef enum _AJOBS_State_Test {
    AJOBS_STATE_NOT_CONFIGURED = 0,
    AJOBS_STATE_CONFIGURED_NOT_VALIDATED = 1,
    AJOBS_STATE_CONFIGURED_VALIDATING = 2,
    AJOBS_STATE_CONFIGURED_VALIDATED = 3,
    AJOBS_STATE_CONFIGURED_ERROR = 4,
    AJOBS_STATE_CONFIGURED_RETRY = 5,
} AJOBS_State_Test;

typedef struct _AJOBS_Info_Test {
    char ssid[33];
    char pc[129];
    AJOBS_AuthType_Test authType;
    AJOBS_State_Test state;
} AJOBS_Info_Test;

void Randomizer() {
    do {
        AJ_RandBytes((uint8_t*) &tid1, sizeof(tid1));
        AJ_Sleep(10);
        AJ_RandBytes((uint8_t*) &tid2, sizeof(tid2));
        AJ_Sleep(10);
        AJ_RandBytes((uint8_t*) &tid3, sizeof(tid3));
        AJ_Sleep(10);
        AJ_RandBytes((uint8_t*) &tid4, sizeof(tid4));
        AJ_InfoPrintf(("Randomizer values: %u %u %u %u\n", tid1, tid2, tid3, tid4));
    } while (tid1 == 0 || tid2 == 0 || tid3 == 0 || tid4 == 0);
}

AJ_Status TestCreds()
{
    AJ_Status status = AJ_OK;
    AJ_GUID localGuid;
    AJ_GUID remoteGuid;
    char str[33];
    uint32_t exp;
    AJ_CredField id;
    AJ_CredField data;
    int i = 0;
    AJ_GUID peerGuid;
    uint8_t secretLen = 24;
    uint8_t secret[24];
    uint32_t expiration = 50898;
    char hex[100];
    AJ_ECCPrivateKey prv1;
    AJ_ECCPrivateKey prv2;
    AJ_ECCPublicKey pub1;
    AJ_ECCPublicKey pub2;

    AJ_AlwaysPrintf(("Start TestCreds\n"));
    status = AJ_GetLocalGUID(&localGuid);
    if (AJ_OK != status) {
        return status;
    }
    AJ_GUID_FromString(&localGuid, str);

    /* Test delete oldest credential by storing more than MAX_CREDS */
    id.data = (uint8_t*) &peerGuid;
    id.size = sizeof (peerGuid);
    data.data = id.data;
    data.size = id.size;
    memset(id.data, 0, id.size);
    for (i = 0; i < 2 * AJ_MAX_CREDS; i++) {
        id.data[0] = i;
        status = AJ_CredentialSet(AJ_CRED_TYPE_GENERIC, &id, (uint32_t) i, &data);
        AJ_ASSERT(AJ_OK == status);
    }

    AJ_InfoPrintf(("TestCreds() Layout Print\n"));
    AJ_NVRAM_Layout_Print();
    memset(&peerGuid, 1, sizeof(AJ_GUID));
    for (i = 0; i < secretLen; i++) {
        secret[i] = i;
    }
    AJ_GUID_ToString(&peerGuid, hex, 100);
    AJ_AlwaysPrintf(("AJ_CredentialSetPeer guid %s\n", hex));
    status = AJ_CredentialSetPeer(AJ_GENERIC_MASTER_SECRET, &peerGuid, expiration, secret, secretLen);
    memcpy(&remoteGuid, &peerGuid, sizeof(AJ_GUID)); // backup the GUID
    if (AJ_OK != status) {
        AJ_AlwaysPrintf(("AJ_CredentialSetPeer failed = %d\n", status));
        return status;
    }
    AJ_NVRAM_Layout_Print();

    AJ_InfoPrintf(("TestCreds() StoreCred() Layout Print\n"));
    AJ_NVRAM_Layout_Print();

    AJ_GUID_ToString(&remoteGuid, hex, 100);
    AJ_AlwaysPrintf(("AJ_CredentialGetPeer guid %s\n", hex));
    data.data = NULL;
    status = AJ_CredentialGetPeer(AJ_GENERIC_MASTER_SECRET, &remoteGuid, &exp, &data);
    if (AJ_OK != status) {
        AJ_AlwaysPrintf(("AJ_CredentialGetPeer failed = %d\n", status));
        return status;
    }

    if (data.size != secretLen) {
        AJ_AlwaysPrintf(("no match for secretLen got %d expected %d\n",
                         data.size, secretLen));
        AJ_CredFieldFree(&data);
        return AJ_ERR_FAILURE;
    }
    if (secretLen > 0) {
        if (0 != memcmp(data.data, secret, secretLen)) {
            AJ_AlwaysPrintf(("no match for secret\n"));
            AJ_CredFieldFree(&data);
            return AJ_ERR_FAILURE;
        }
    }
    if (exp != expiration) {
        AJ_AlwaysPrintf(("no match for expiration got %d expected %d\n",
                         exp, expiration));
        AJ_CredFieldFree(&data);
        return AJ_ERR_FAILURE;
    }

    AJ_CredentialDeletePeer(&remoteGuid);
    AJ_CredFieldFree(&data);
    if (AJ_ERR_UNKNOWN == AJ_CredentialGetPeer(AJ_GENERIC_MASTER_SECRET, &remoteGuid, NULL, NULL)) {
        status = AJ_OK;
    } else {
        return AJ_ERR_FAILURE;
    }
    AJ_InfoPrintf(("TestCreds() Layout Print\n"));
    AJ_NVRAM_Layout_Print();

    AJ_ClearCredentials(0);
    if (AJ_ERR_UNKNOWN == AJ_CredentialGetPeer(AJ_GENERIC_MASTER_SECRET, &remoteGuid, NULL, NULL)) {
        status = AJ_OK;
    } else {
        return AJ_ERR_FAILURE;
    }
    AJ_InfoPrintf(("TestCreds() Layout Print\n"));
    AJ_NVRAM_Layout_Print();
    AJ_AlwaysPrintf(("TestCreds done.\n"));

    status = AJ_GenerateECCKeyPair(&pub1, &prv1);
    AJ_ASSERT(AJ_OK == status);

    status = AJ_CredentialSetECCPublicKey(AJ_ECC_SIG, NULL, 0xFFFFFFFF, &pub1);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_CredentialSetECCPrivateKey(AJ_ECC_SIG, NULL, 0xFFFFFFFF, &prv1);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_CredentialGetECCPublicKey(AJ_ECC_SIG, NULL, NULL, &pub2);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_CredentialGetECCPrivateKey(AJ_ECC_SIG, NULL, NULL, &prv2);
    AJ_ASSERT(AJ_OK == status);

    AJ_ASSERT(0 == memcmp((uint8_t*) &pub1, (uint8_t*) &pub2, sizeof (pub1)));
    AJ_ASSERT(0 == memcmp((uint8_t*) &prv1, (uint8_t*) &prv2, sizeof (prv1)));

    return status;
}

AJ_Status TestExist()
{
    AJ_Status status = AJ_OK;

#ifdef EXIST_STRESS
    while (TRUE) {
#endif
    AJ_InfoPrintf(("POSITIVE EXIST STATUS = %u\n", status = AJ_NVRAM_Exist(AJ_LOCAL_GUID_NV_ID)));
    if (status < 0) {
        return status;
    }

    AJ_InfoPrintf(("NEGATIVE EXIST STATUS = %u\n", status = AJ_NVRAM_Exist(66)));
    if (status < 0) {
        return status;
    }

#ifdef EXIST_STRESS
}
#endif
    return status;
}


AJ_Status TestObsWrite()
{
    AJ_Status status = AJ_OK;
    AJ_NV_DATASET* nvramHandle;
    AJOBS_Info_Test info;
    size_t size = sizeof(info);
    const char* ssid[] = { "abcdefghABCDEFGH", "aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd", "eeeeeeee", "ffffffff", "gggggggg", "hhhhhhhh", "iiiiiiii",
                           "jjjjjjjj", "kkkkkkkk", "llllllll", "mmmmmmmm", "nnnnnnnn", "oooooooo", "pppppppp", "qqqqqqqq", "rrrrrrrr", "ssssssss",
                           "", "tttttttt", "uuuuuuuu", "vvvvvvvv", "wwwwwwww", "xxxxxxxx", "yyyyyyyy", "zzzzzzzz", "11111111", "22222222", "33333333",
                           "44444444", "55555555", "66666666", "77777777", "888888888888888888888888888888", "99999999", "aaaa1111", "bbbb2222", "cccc3333", "dddd4444",
                           "TRTESTING123", "eeee5555", "", "TR-TESTING-43" };
    char pc[] = "aaaaabbbbbcccccAAAAABBBBBCCCCCzzzzzZZZZZ1111122222";
    size_t i;

    AJ_NVRAM_Layout_Print();

    //if( AJ_NVRAM_Exist(AJ_NVRAM_ID_SERVICES_BEGIN + 99)){ //NEGATIVE TEST, ID DOESN'T EXIST
    //if( AJ_NVRAM_Exist(AJ_NVRAM_ID_SERVICES_BEGIN + 1)){ //PROPERTY STORE DEVICE ID
    if (AJ_NVRAM_Exist(AJ_NVRAM_ID_APPS_BEGIN)) {
        //nvramHandle = AJ_NVRAM_Open(100, "r", 0); //NEGATIVE TEST, OPEN INVALID ID
        //nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_SERVICES_BEGIN, "r", 0); //PROPERTY STORE DEVICE ID
        nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_APPS_BEGIN, "r", 0);
        if (nvramHandle != NULL) {
            int sizeRead = AJ_NVRAM_Read(&info, size, nvramHandle);
            status = AJ_NVRAM_Close(nvramHandle);
            AJ_InfoPrintf(("sizeRead: %u, size: %u\n", sizeRead, size));
            if (sizeRead != size) {
                status = AJ_ERR_READ;
            } else {
                AJ_InfoPrintf(("Read Info values: state=%d, ssid=%s authType=%d pc=%s\n", info.state, info.ssid, info.authType, info.pc));
            }
        }
    }

    //nTest = AJ_NVRAM_Read(&info, size, nvramHandle); //NEGATIVE TEST, READ NULL HANDLE
    //nTest = AJ_NVRAM_Write(&info, size, nvramHandle); //NEGATIVE TEST, WRITE TO NULL HANDLE

    for (i = 0; i < ArraySize(ssid); i++) {
        strncpy(info.ssid, ssid[i], sizeof(info.ssid));
        strncpy(info.pc, pc, sizeof(info.pc));
        info.authType = 0;
        info.state = 0;

#ifdef OBS_STRESS
        while (TRUE) {
#endif

#ifdef SHOW_REWRITES
        AJ_AlwaysPrintf(("Going to write Info values: state=%d, ssid=%s authType=%d pc=%s\n", info.state, info.ssid, info.authType, info.pc));
#endif

        //nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_SERVICES_BEGIN, "w", 0); //NEGATIVE TEST, OPEN 0 SIZE
        //nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_SERVICES_BEGIN, "t", size); //NEGATIVE TEST, INVALID MODE
        //nvramHandle = AJ_NVRAM_Open(0, "w", size); //NEGATIVE TEST, OPEN 0 ID
        //nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_SERVICES_BEGIN, "w", size); //PROPERTY STORE DEVICE ID
        nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_APPS_BEGIN, "w", size);
        if (nvramHandle != NULL) {
            int sizeWritten = AJ_NVRAM_Write(&info, size, nvramHandle);
            status = AJ_NVRAM_Close(nvramHandle);
            if (sizeWritten != size) {
                status = AJ_ERR_WRITE;
            }
        }
        //nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_SERVICES_BEGIN, "r", 0); //PROPERTY STORE DEVICE ID
        nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_APPS_BEGIN, "r", 0);
        if (nvramHandle != NULL) {
            int sizeRead = AJ_NVRAM_Read(&info, size, nvramHandle);
            status = AJ_NVRAM_Close(nvramHandle);
            if (sizeRead != sizeRead) {
                status = AJ_ERR_READ;
            }
#ifdef SHOW_REWRITES
            else {
                AJ_InfoPrintf(("Read Info values: state=%d, ssid=%s authType=%d pc=%s\n", info.state, info.ssid, info.authType, info.pc));
            }
#endif
        }

#ifdef NEGATIVE_OPEN
        nvramHandle = AJ_NVRAM_Open(66, "r", 0);
        status = AJ_NVRAM_Close(nvramHandle);
#endif

        //AJ_NVRAM_Layout_Print();
#ifdef OBS_STRESS
        AJ_Sleep(2000);
    }
#endif
    }
    AJ_NVRAM_Layout_Print();
    return status;
}


AJ_Status TestNvramWrite()
{
    AJ_NV_DATASET* d1 = NULL;
    AJ_NV_DATASET* d2 = NULL;
    AJ_NV_DATASET* d3 = NULL;
    AJ_NV_DATASET* d4 = NULL;
    int i = 0;
    uint16_t cap1, cap2, cap3, cap4 = 0;
    size_t bytes1, bytes2, bytes3, bytes4 = 0;
    AJ_Status status = AJ_OK;

#ifdef WRITE_STRESS
    while (TRUE) {
#endif
    cap1 = (tid1 % ((AJ_NVRAM_REQUESTED / 4) - 100)) + 1;
    cap2 = (tid2 % ((AJ_NVRAM_REQUESTED / 4) - 100)) + 1;
    cap3 = (tid3 % ((AJ_NVRAM_REQUESTED / 4) - 100)) + 1;
    cap4 = (tid4 % ((AJ_NVRAM_REQUESTED / 4) - 100)) + 1;

    d1 = AJ_NVRAM_Open(tid1, "w", cap1);
    for (i = 0; i < AJ_NVRAM_REQUESTED / 4; i++) {
        if ((d1->capacity - d1->curPos) >= sizeof(i)) {
            bytes1 = AJ_NVRAM_Write(&i, sizeof(i), d1);
            if (bytes1 != sizeof(i)) {
                return AJ_ERR_FAILURE;
            }
        }
    }
    AJ_InfoPrintf(("Dataset1 bytes: %u i: %u sizeof(i): %u capacity %u curPos %u\n", bytes1, i, sizeof(i), d1->capacity, d1->curPos));
    AJ_InfoPrintf(("LAYOUT AFTER WRITE\n"));
    AJ_NVRAM_Layout_Print();
    if (d1 != NULL) {
        AJ_NVRAM_Close(d1);
        AJ_ASSERT(d1);
    }

    d2 = AJ_NVRAM_Open(tid2, "w", cap2);
    AJ_ASSERT(d2);
    for (i = 0; i < AJ_NVRAM_REQUESTED / 4; i++) {
        if ((d2->capacity - d2->curPos) >= sizeof(i)) {
            bytes2 = AJ_NVRAM_Write(&i, sizeof(i), d2);
            if (bytes2 != sizeof(i)) {
                return AJ_ERR_FAILURE;
            }
        }
    }
    AJ_InfoPrintf(("Dataset2 bytes: %u i: %u sizeof(i): %u capacity %u curPos %u\n", bytes2, i, sizeof(i), d2->capacity, d2->curPos));
    AJ_InfoPrintf(("LAYOUT AFTER WRITE\n"));
    AJ_NVRAM_Layout_Print();
    if (d2 != NULL) {
        AJ_NVRAM_Close(d2);
        AJ_ASSERT(d2);
    }


    d3 = AJ_NVRAM_Open(tid3, "w", cap3);
    AJ_ASSERT(d3);
    for (i = 0; i < AJ_NVRAM_REQUESTED / 4; i++) {
        if ((d3->capacity - d3->curPos) >= sizeof(i)) {
            bytes3 = AJ_NVRAM_Write(&i, sizeof(i), d3);
            if (bytes3 != sizeof(i)) {
                return AJ_ERR_FAILURE;
            }
        }
    }
    AJ_InfoPrintf(("Dataset3 bytes: %u i: %u sizeof(i): %u capacity %u curPos %u\n", bytes2, i, sizeof(i), d2->capacity, d2->curPos));
    AJ_InfoPrintf(("LAYOUT AFTER WRITE\n"));
    AJ_NVRAM_Layout_Print();
    if (d3 != NULL) {
        AJ_NVRAM_Close(d3);
        AJ_ASSERT(d3);
    }

    d4 = AJ_NVRAM_Open(tid4, "w", cap4);
    AJ_ASSERT(d4);
    for (i = 0; i < AJ_NVRAM_REQUESTED / 4; i++) {
        if ((d4->capacity - d4->curPos) >= sizeof(i)) {
            bytes4 = AJ_NVRAM_Write(&i, sizeof(i), d4);
            if (bytes4 != sizeof(i)) {
                return AJ_ERR_FAILURE;
            }
        }
    }
    AJ_InfoPrintf(("Dataset4 bytes: %u i: %u sizeof(i): %u capacity %u curPos %u\n", bytes2, i, sizeof(i), d2->capacity, d2->curPos));
    AJ_InfoPrintf(("LAYOUT AFTER WRITE\n"));
    AJ_NVRAM_Layout_Print();
    if (d4 != NULL) {
        AJ_NVRAM_Close(d4);
        AJ_ASSERT(d4);
    }

    AJ_InfoPrintf(("LAYOUT AFTER CLOSE - WRITE MODE\n"));
    AJ_NVRAM_Layout_Print();
#ifdef WRITE_STRESS
}
#endif
    return status;
}

AJ_Status TestNvramRead() {
    //uint16_t id = 0;
    AJ_NV_DATASET* d1 = NULL;
    AJ_NV_DATASET* d2 = NULL;
    AJ_NV_DATASET* d3 = NULL;
    AJ_NV_DATASET* d4 = NULL;
    int i = 0;
    size_t bytes1, bytes2, bytes3, bytes4 = 0;
    AJ_Status status = AJ_OK;

    AJ_NVRAM_Layout_Print();

#ifdef READ_STRESS
    while (TRUE) {
#endif
    //AJ_InfoPrintf(("LAYOUT AFTER OPEN - READ MODE\n"));
    //AJ_NVRAM_Layout_Print();

    d1 = AJ_NVRAM_Open(tid1, "r", 0);
    //d1 = AJ_NVRAM_Open(66, "r", 0); //NEGATIVE READ TEST
    AJ_ASSERT(d1);
    for (i = 0; i < d1->capacity / 4; i++) {
        int data1 = 0;
        bytes1 = AJ_NVRAM_Read(&data1, sizeof(data1), d1);
        if (bytes1 != sizeof(data1) || data1 != i) {
            return AJ_ERR_FAILURE;
        }
#ifdef SHOW_READ
        if (i % 10 == 0) {
            AJ_InfoPrintf(("Dataset 1 capacity %u curPos %u flash value: %u\n", d1->capacity, d1->curPos, data1));
        }
#endif
    }
    if (d1 != NULL) {
        AJ_NVRAM_Close(d1);
        AJ_ASSERT(d1);
    }

    d2 = AJ_NVRAM_Open(tid2, "r", 0);
    AJ_ASSERT(d2);
    for (i = 0; i < d2->capacity / 4; i++) {
        int data2 = 0;
        bytes2 = AJ_NVRAM_Read(&data2, sizeof(data2), d2);
        if (bytes2 != sizeof(data2) || data2 != i) {
            return AJ_ERR_FAILURE;
        }
#ifdef SHOW_READ
        if (i % 10 == 0) {
            AJ_InfoPrintf(("Dataset 2 capacity %u curPos %u flash value: %u\n", d2->capacity, d2->curPos, data2));
        }
#endif
    }
    if (d2 != NULL) {
        AJ_NVRAM_Close(d2);
        AJ_ASSERT(d2);
    }

    d3 = AJ_NVRAM_Open(tid3, "r", 0);
    AJ_ASSERT(d3);
    for (i = 0; i < d3->capacity / 4; i++) {
        int data3 = 0;
        bytes3 = AJ_NVRAM_Read(&data3, sizeof(data3), d3);
        if (bytes3 != sizeof(data3) || data3 != i) {
            return AJ_ERR_FAILURE;
        }
#ifdef SHOW_READ
        if (i % 10 == 0) {
            AJ_InfoPrintf(("Dataset 3 capacity %u curPos %u flash value: %u\n", d3->capacity, d3->curPos, data3));
        }
#endif
    }
    if (d3 != NULL) {
        AJ_NVRAM_Close(d3);
        AJ_ASSERT(d3);
    }

    d4 = AJ_NVRAM_Open(tid4, "r", 0);
    AJ_ASSERT(d4);
    for (i = 0; i < d4->capacity / 4; i++) {
        int data4 = 0;
        bytes4 = AJ_NVRAM_Read(&data4, sizeof(data4), d4);
        if (bytes4 != sizeof(data4) || data4 != i) {
            return AJ_ERR_FAILURE;
        }
#ifdef SHOW_READ
        if (i % 10 == 0) {
            AJ_InfoPrintf(("Dataset 4 capacity %u curPos %u flash value: %u\n", d4->capacity, d4->curPos, data4));
        }
#endif
    }
    if (d4 != NULL) {
        AJ_NVRAM_Close(d4);
        AJ_ASSERT(d4);
    }

    AJ_InfoPrintf(("LAYOUT AFTER READ --- END capacity %u curPos %u\n", d4->capacity, d4->curPos));
    AJ_NVRAM_Layout_Print();

#ifdef READ_STRESS
}
#endif
    return status;
}


AJ_Status TestNvramDelete()
{
    AJ_Status status = AJ_OK;
    AJ_NV_DATASET* nvramHandle;

    if (tid1 % 2 == 1) {
#ifndef OBS_ONLY
        if (AJ_NVRAM_Exist(tid1)) {
            AJ_ASSERT(AJ_NVRAM_Delete(tid1) == AJ_OK);
        }
        AJ_InfoPrintf(("LAYOUT AFTER DELETE 1\n"));
        AJ_NVRAM_Layout_Print();

        if (AJ_NVRAM_Exist(tid2)) {
            AJ_ASSERT(AJ_NVRAM_Delete(tid2) == AJ_OK);
        }
        AJ_InfoPrintf(("LAYOUT AFTER DELETE 2\n"));
        AJ_NVRAM_Layout_Print();

        if (AJ_NVRAM_Exist(tid3)) {
            AJ_ASSERT(AJ_NVRAM_Delete(tid3) == AJ_OK);
        }
        AJ_InfoPrintf(("LAYOUT AFTER DELETE 3\n"));
        AJ_NVRAM_Layout_Print();

        if (AJ_NVRAM_Exist(tid4)) {
            AJ_ASSERT(AJ_NVRAM_Delete(tid4) == AJ_OK);
        }
        AJ_InfoPrintf(("LAYOUT AFTER DELETE 4\n"));
        AJ_NVRAM_Layout_Print();
#endif

        if (AJ_NVRAM_Exist(AJ_NVRAM_ID_APPS_BEGIN)) {
            AJOBS_Info_Test emptyInfo;
            size_t size = sizeof(AJOBS_Info_Test);

            memset(&emptyInfo, 0, sizeof(emptyInfo));
            AJ_AlwaysPrintf(("Going to write Info values: state=%d, ssid=%s authType=%d pc=%s\n", emptyInfo.state, emptyInfo.ssid, emptyInfo.authType, emptyInfo.pc));
            //AJ_NV_DATASET* nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_SERVICES_BEGIN, "w", size); //PROPERTY STORE DEVICE ID
            nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_APPS_BEGIN, "w", size);
            if (nvramHandle != NULL) {
                int sizeWritten = AJ_NVRAM_Write(&emptyInfo, size, nvramHandle);
                status = AJ_NVRAM_Close(nvramHandle);
                if (sizeWritten != size) {
                    status = AJ_ERR_WRITE;
                    goto _TEST_NVRAM_DELETE_EXIT;
                }
            }
            //nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_SERVICES_BEGIN, "r", 0); //PROPERTY STORE DEVICE ID
            nvramHandle = AJ_NVRAM_Open(AJ_NVRAM_ID_APPS_BEGIN, "r", 0);
            if (nvramHandle != NULL) {
                int sizeRead = AJ_NVRAM_Read(&emptyInfo, size, nvramHandle);
                status = AJ_NVRAM_Close(nvramHandle);
                if (sizeRead != sizeRead) {
                    status = AJ_ERR_READ;
                } else {
                    AJ_AlwaysPrintf(("Read Info values: state=%d, ssid=%s authType=%d pc=%s\n", emptyInfo.state, emptyInfo.ssid, emptyInfo.authType, emptyInfo.pc));
                }
            }
        }
        AJ_InfoPrintf(("LAYOUT AFTER DELETE OBS\n"));
        AJ_NVRAM_Layout_Print();
    } else {
        AJ_NVRAM_Clear();
        AJ_InfoPrintf(("LAYOUT AFTER CLEAR ALL\n"));
        AJ_NVRAM_Layout_Print();
    }
    return status;

_TEST_NVRAM_DELETE_EXIT:
    AJ_NVRAM_Close(nvramHandle);
    return status;

}

AJ_Status TestNVRAMPeek()
{
    AJ_Status status = AJ_OK;
    AJ_NV_DATASET* handle = NULL;
    size_t bytes = 0;
    char buffer[] = "This is a test buffer";
    uint8_t buffer_raw[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    char* ptr;
    uint8_t* ptr_raw;
    AJ_AlwaysPrintf(("Testing AJ_NVRAM_Peek()\n"));
    /*
     * String pointer data test
     */
    handle = AJ_NVRAM_Open(999, "w", strlen(buffer) + 1);
    if (handle) {
        bytes = AJ_NVRAM_Write(buffer, strlen(buffer) + 1, handle);
        if (bytes != strlen(buffer) + 1) {
            return AJ_ERR_FAILURE;
        }
    } else {
        return AJ_ERR_FAILURE;
    }
    status = AJ_NVRAM_Close(handle);
    if (status == AJ_OK) {
        handle = AJ_NVRAM_Open(999, "r", strlen(buffer) + 1);
        ptr = (char*)AJ_NVRAM_Peek(handle);
        if (!ptr || (strcmp(ptr, buffer) != 0)) {
            AJ_ErrPrintf(("Strings do not match: buffer = %s, return = %s\n", buffer, ptr));
            return AJ_ERR_FAILURE;
        }
        status = AJ_NVRAM_Close(handle);
    }
    /*
     * Raw data pointer test
     */
    handle = AJ_NVRAM_Open(1000, "w", ArraySize(buffer_raw));
    if (handle) {
        bytes = AJ_NVRAM_Write(buffer_raw, ArraySize(buffer_raw), handle);
        if (bytes != ArraySize(buffer_raw)) {
            return AJ_ERR_FAILURE;
        }
    }
    status = AJ_NVRAM_Close(handle);
    if (status == AJ_OK) {
        handle = AJ_NVRAM_Open(1000, "r", ArraySize(buffer_raw));
        ptr_raw = (uint8_t*)AJ_NVRAM_Peek(handle);
        if (!ptr || (memcmp(buffer_raw, ptr_raw, ArraySize(buffer_raw)) != 0)) {
            AJ_ErrPrintf(("Raw data does not match\n"));
            return AJ_ERR_FAILURE;
        }
        status = AJ_NVRAM_Close(handle);
    }
    AJ_NVRAM_Layout_Print();
    AJ_AlwaysPrintf(("Testing AJ_NVRAM_Peek() done\n"));
    return status;
}

AJ_Status TestNVRAMBigWrite()
{
    AJ_Status status = AJ_OK;
    AJ_NV_DATASET* handle = NULL;
    uint8_t* write_bytes;
    uint8_t* read_bytes;
    size_t bytes;
    int i;
    uint16_t size = 40000;

    if (size > AJ_NVRAM_REQUESTED) {
        AJ_AlwaysPrintf(("Testing big write not possible, NVRAM not big enough\n"));
        return AJ_OK;
    }

    write_bytes = AJ_Malloc(size);
    read_bytes = AJ_Malloc(size);
    if (!write_bytes || !read_bytes) {
        AJ_ErrPrintf(("malloc failed\n"));
        return AJ_ERR_FAILURE;
    }
    memset(write_bytes, 0x54, size);
    memset(read_bytes, 0x45, size);

    handle = AJ_NVRAM_Open(1234, "w", size);
    if (!handle) {
        AJ_ErrPrintf(("Unable to open big write ID\n"));
        return AJ_ERR_FAILURE;
    }

    bytes = AJ_NVRAM_Write(write_bytes, size, handle);
    if (bytes != (size_t) size) {
        AJ_ErrPrintf(("Unable to write big bytes\n"));
        return AJ_ERR_FAILURE;
    }

    status = AJ_NVRAM_Close(handle);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("Unable to close big write ID\n"));
        return AJ_ERR_FAILURE;
    }

    handle = AJ_NVRAM_Open(1234, "r", 0);
    if (!handle) {
        AJ_ErrPrintf(("Unable to open big read ID\n"));
        return AJ_ERR_FAILURE;
    }

    bytes = AJ_NVRAM_Read(read_bytes, size, handle);
    if (bytes != (size_t) size) {
        AJ_ErrPrintf(("Unable to read big bytes\n"));
        return AJ_ERR_FAILURE;
    }

    for (i = 0; i < size; i++) {
        if (write_bytes[i] != read_bytes[i]) {
            AJ_ErrPrintf(("big bytes mismatch at offset %d\n", i));
            return AJ_ERR_FAILURE;
        }
    }

    status = AJ_NVRAM_Close(handle);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("Unable to close big read ID\n"));
        return AJ_ERR_FAILURE;
    }

    AJ_AlwaysPrintf(("Testing Big Write done\n"));
    return AJ_OK;

}

AJ_Status TestNVRAM()
{
    uint16_t id = 16;
    AJ_NV_DATASET* handle = NULL;
    int i = 0;
    size_t bytes = 0;
    AJ_Status status = AJ_OK;
    AJ_NVRAM_Layout_Print();

    {
        handle = AJ_NVRAM_Open(id, "w", 40 + 5);
        AJ_NVRAM_Layout_Print();
        AJ_ASSERT(handle);

        for (i = 0; i < 10; i++) {
            bytes = AJ_NVRAM_Write(&i, sizeof(i), handle);
            if (bytes != sizeof(i)) {
                status = AJ_ERR_FAILURE;
                goto _TEST_NVRAM_EXIT;
            }
        }
        {
            uint8_t buf[3] = { 11, 22, 33 };
            uint8_t buf2[2] = { 44, 55 };
            bytes = AJ_NVRAM_Write(buf, sizeof(buf), handle);
            if (bytes != sizeof(buf)) {
                status = AJ_ERR_FAILURE;
                goto _TEST_NVRAM_EXIT;
            }
            bytes = AJ_NVRAM_Write(buf2, sizeof(buf2), handle);
            if (bytes != sizeof(buf2)) {
                status = AJ_ERR_FAILURE;
                goto _TEST_NVRAM_EXIT;
            }

        }
        AJ_NVRAM_Close(handle);
        AJ_InfoPrintf(("TestNVRAM() Layout Print\n"));
        AJ_NVRAM_Layout_Print();

        handle = AJ_NVRAM_Open(id, "r", 0);
        AJ_ASSERT(handle);
        for (i = 0; i < 10; i++) {
            int data = 0;
            bytes = AJ_NVRAM_Read(&data, sizeof(data), handle);
            if (bytes != sizeof(data) || data != i) {
                status = AJ_ERR_FAILURE;
                goto _TEST_NVRAM_EXIT;
            }
        }
        for (i = 1; i < 6; i++) {
            uint8_t data = 0;
            AJ_NVRAM_Read(&data, 1, handle);
            if (data != i * 11) {
                status = AJ_ERR_FAILURE;
                goto _TEST_NVRAM_EXIT;
            }
        }
        AJ_NVRAM_Close(handle);
    }

    if (AJ_NVRAM_Exist(id + 1)) {
        AJ_ASSERT(AJ_NVRAM_Delete(id + 1) == AJ_OK);
    }

    // Force storage compaction
    for (i = 0; i < 12; i++) {
        if (i == 6) {
            handle = AJ_NVRAM_Open(id + 2, "w", 100);
            AJ_ASSERT(handle);
            status = AJ_NVRAM_Close(handle);
            if (AJ_OK != status) {
                goto _TEST_NVRAM_EXIT;
            }
            continue;
        }
        handle = AJ_NVRAM_Open(id + 1, "w", 200);
        AJ_ASSERT(handle);
        status = AJ_NVRAM_Close(handle);
        if (AJ_OK != status) {
            goto _TEST_NVRAM_EXIT;
        }
    }
    AJ_InfoPrintf(("Compaction Layout Print\n"));
    AJ_NVRAM_Layout_Print();

_TEST_NVRAM_EXIT:
    //AJ_NVRAM_Close(handle);
    return status;
}

int AJ_Main()
{
    AJ_Status status = AJ_OK;
    while (status == AJ_OK) {
        AJ_AlwaysPrintf(("AJ Initialize\n"));
        AJ_Initialize();

#ifdef OBS_ONLY
        AJ_RandBytes(&oRand, sizeof(oRand));
        AJ_InfoPrintf(("BEGIN OBSWRITE TEST\n"));
        status = testObsWrite();
        if (oRand % 2 == 0) {
            AJ_InfoPrintf(("CALLING REBOOT WITHOUT REWRITING TO 0"));
#ifdef READABLE_LOG
            AJ_Sleep(1500);
#endif
            AJ_Reboot();
        }
        AJ_InfoPrintf(("REWRITE OBS TO 0 AND READ TEST\n"));
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif
        status = TestNvramDelete();
        AJ_Reboot();
#endif
        AJ_NVRAM_Clear();

        AJ_AlwaysPrintf(("TEST LOCAL AND REMOTE CREDS\n"));
        status = TestCreds();
        AJ_ASSERT(status == AJ_OK);
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif

        AJ_AlwaysPrintf(("AJ_Main 2\n"));
        status = TestNVRAM();
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif

#ifdef RAND_DATA
        Randomizer();
#endif
        AJ_InfoPrintf(("\nBEGIN GUID EXIST TEST\n"));
        status = TestExist();
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif
        AJ_InfoPrintf(("\nBEGIN OBSWRITE TEST\n"));
        status = TestObsWrite();
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif

        AJ_InfoPrintf(("\nOBSWRITE STATUS %u, BEGIN WRITE TEST\n", status));
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif
        status = TestNvramWrite();
        AJ_InfoPrintf(("\nWRITE STATUS %u, BEGIN READ TEST\n", status));
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif
        status = TestNvramRead();
        AJ_InfoPrintf(("\nREAD STATUS %u, BEGIN DELETE TEST\n", status));
#ifdef READABLE_LOG
        AJ_Sleep(1500);
#endif
        status = TestNvramDelete();
        AJ_InfoPrintf(("\nDONE\n"));

        AJ_AlwaysPrintf(("AJ_Main 3\n"));
        AJ_ASSERT(status == AJ_OK);

        AJ_AlwaysPrintf(("\nDELETE STATUS %u, NVRAMTEST RUN %u TIMES\n", status, count++));
#ifdef READABLE_LOG
        AJ_Sleep(3000);
#endif

        status = TestNVRAMPeek();
        AJ_InfoPrintf(("\nNVRAM Peek STATUS %u\n", status));
        AJ_ASSERT(status == AJ_OK);

        status = TestNVRAMBigWrite();
        AJ_InfoPrintf(("\nNVRAM Big Write STATUS %u\n", status));
        AJ_ASSERT(status == AJ_OK);

    }
    return 0;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
