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

#define AJ_MODULE NVRAMDUMP

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_creds.h>

uint8_t dbgNVRAMDUMP = 1;
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
    uint16_t type;
    AJ_CredField id;
    uint32_t expiration;
    AJ_CredField data;

    AJ_NVRAM_Layout_Print();
    AJ_AlwaysPrintf(("Remaining Size %d\n", AJ_NVRAM_GetSizeRemaining()));

    AJ_AlwaysPrintf(("SLOT | TYPE | ID | EXPIRATION | DATA\n"));
    for (; slot < AJ_CREDS_NV_ID_END; slot++) {
        if (!AJ_NVRAM_Exist(slot)) {
            continue;
        }
        id.data = NULL;
        data.data = NULL;
        status = AJ_CredentialRead(&type, &id, &expiration, &data, slot);
        if (AJ_OK == status) {
            AJ_AlwaysPrintf(("%04X | %04X | ", slot, type));
            printhex(id.data, id.size);
            AJ_AlwaysPrintf((" | %08X | ", expiration));
            //printhex(data.data, data.size);
            AJ_DumpBytes("", data.data, data.size);
            AJ_AlwaysPrintf(("\n"));
            AJ_CredFieldFree(&id);
            AJ_CredFieldFree(&data);
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
