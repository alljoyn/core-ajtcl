#ifndef _AJ_CERT_H
#define _AJ_CERT_H
/**
 * @file
 *
 * Header file for certificate utilities
 */

/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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

#include "aj_guid.h"
#include "aj_crypto_ecc.h"
#include "aj_crypto_sha2.h"

#define MAX_NUM_CERTIFICATES 2

/*
 * Certificate types are native.
 * Conversion to network byte-order (big-endian) is done via encoding and decoding.
 */
typedef struct _AJ_Validity {
    uint64_t validfrom;
    uint64_t validto;
} AJ_Validity;

#define AJ_GUID_LENGTH (sizeof (AJ_GUID))
typedef struct _AJ_Certificate {
    uint32_t version;
    ecc_publickey issuer;
    ecc_publickey subject;
    AJ_Validity validity;
    uint8_t delegate;
    uint8_t guild[AJ_GUID_LENGTH];
    uint8_t digest[SHA256_DIGEST_LENGTH];
    ecc_signature signature;
    uint32_t size;
} AJ_Certificate;

void U32ToU8(uint32_t* u32, size_t len, uint8_t* u8);
AJ_Status AJ_EncodePublicKey(ecc_publickey* publickey, uint8_t* b8);
AJ_Status AJ_DecodePublicKey(ecc_publickey* publickey, uint8_t* b8);
AJ_Status AJ_EncodePrivateKey(ecc_privatekey* privatekey, uint8_t* b8);
AJ_Status AJ_DecodePrivateKey(ecc_privatekey* privatekey, uint8_t* b8);
AJ_Status AJ_EncodeCertificate(AJ_Certificate* certificate, uint8_t* b8, size_t b8len);
AJ_Status AJ_DecodeCertificate(AJ_Certificate* certificate, uint8_t* b8, size_t b8len);
AJ_Status AJ_CreateCertificate(AJ_Certificate* certificate, const uint32_t version, const ecc_publickey* issuer, const ecc_publickey* subject, const AJ_GUID* guild, const uint8_t* digest, const uint8_t delegate);
AJ_Status AJ_SignCertificate(AJ_Certificate* certificate, const ecc_privatekey* issuer_private);
AJ_Status AJ_VerifyCertificate(AJ_Certificate* certificate);
void AJ_PrintCertificate(AJ_Certificate* certificate);

#endif
