/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
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

#include <alljoyn.h>
#include <aj_creds.h>
#include <aj_nvram.h>
#include <aj_crypto_ecc.h>

extern void AJ_NVRAM_Layout_Print();
AJ_Status DumpNVRAM();

void printhex(uint8_t*x, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        AJ_AlwaysPrintf(("%02X", x[i]));
    }
}

AJ_Status DumpNVRAM()
{
    AJ_Status status;
    uint16_t slot = AJ_CREDS_NV_ID_BEGIN;
    AJ_PeerCred cred;

    AJ_NVRAM_Layout_Print();
    AJ_AlwaysPrintf(("Remaining Size %d\n", AJ_NVRAM_GetSizeRemaining()));

    AJ_AlwaysPrintf(("SLOT | TYPE | ID | EXPIRATION | ASSOCIATION | DATA\n"));
    for (; slot < AJ_CREDS_NV_ID_END; slot++) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        status = AJ_ReadCredential(&cred, slot);
        if (AJ_OK == status) {
            AJ_AlwaysPrintf(("%04X | %04X | ", slot, cred.head.type));
            printhex(cred.head.id.data, cred.head.id.size);
            AJ_AlwaysPrintf((" | %08X | ", cred.body.expiration));
            printhex(cred.body.association.data, cred.body.association.size);
            AJ_AlwaysPrintf((" | "));
            printhex(cred.body.data.data, cred.body.data.size);
            AJ_AlwaysPrintf(("\n"));
            AJ_PeerCredFree(&cred);
        }
    }
    return AJ_OK;
}

int AJ_Main()
{
    AJ_Status status = AJ_OK;
    AJ_Initialize();
    //AJ_NVRAM_Clear();
    //AJ_AlwaysPrintf(("Clearing NVRAM\n"));
    status = DumpNVRAM();
    AJ_ASSERT(status == AJ_OK);
    //AJ_DumpPolicy();
    return 0;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
