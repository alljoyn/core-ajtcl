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

#define AJ_MODULE NVRAMDUMP

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_nvram.h>
#include <ajtcl/aj_crypto_ecc.h>

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

#ifdef MAIN_ALLOWS_ARGS
int AJ_Main(int argc, char** argv)
#else
int AJ_Main(void)
#endif
{
    AJ_Status status;
    AJ_NVRAM_Block_Id _blockId;
    uint8_t useNewLayout = FALSE;
#ifdef MAIN_ALLOWS_ARGS
    uint8_t i;
    for (i = 1; i < argc; ++i) {
        if (0 == strcmp("--newlayout", argv[i])) {
            useNewLayout = TRUE;
        }
    }
#endif
    if (useNewLayout) {
        AJ_NVRAM_Init_NewLayout();
    }
    AJ_Initialize();
    status = DumpNVRAM();
    AJ_ASSERT(status == AJ_OK);
    AJ_AlwaysPrintf(("NVRAM total used size: %d\n", AJ_NVRAM_GetSize_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS)));
    AJ_AlwaysPrintf(("NVRAM total free size: %d\n", AJ_NVRAM_GetSizeRemaining_NewLayout(AJ_NVRAM_ID_ALL_BLOCKS)));
    _blockId = AJ_NVRAM_ID_ALL_BLOCKS;
    if (useNewLayout) {
        for (++_blockId; _blockId < AJ_NVRAM_ID_END_SENTINEL; ++_blockId) {
            AJ_AlwaysPrintf(("NVRAM total used size of block %d: %d\n", _blockId, AJ_NVRAM_GetSize_NewLayout(_blockId)));
            AJ_AlwaysPrintf(("NVRAM total free size of block %d: %d\n", _blockId, AJ_NVRAM_GetSizeRemaining_NewLayout(_blockId)));
        }
    }

    return ((status == AJ_OK) ? 0 : -1);
}

#ifdef AJ_MAIN
#ifdef MAIN_ALLOWS_ARGS
int main(int argc, char** argv)
{
    return AJ_Main(argc, argv);
}
#else
int main()
{
    return AJ_Main();
}
#endif
#endif