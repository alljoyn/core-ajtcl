/**
 * @file
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
#define AJ_MODULE TEST_CERTIFICATE

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "aj_debug.h"
#include "alljoyn.h"
#include "aj_cert.h"
#include "aj_crypto.h"

uint8_t dbgTEST_CERTIFICATE = 0;

static const char intfc[] = "org.alljoyn.test";

static void CreateManifest(uint8_t** manifest, size_t* len)
{
    *len = strlen(intfc);
    *manifest = (uint8_t*) AJ_Malloc(*len);
    AJ_ASSERT(*manifest);
    memcpy(*manifest, (uint8_t*) intfc, *len);
}

static void ManifestDigest(uint8_t* manifest, size_t* len, uint8_t* digest)
{
    AJ_SHA256_Context sha;
    AJ_SHA256_Init(&sha);
    AJ_SHA256_Update(&sha, (const uint8_t*) manifest, *len);
    AJ_SHA256_Final(&sha, digest);
}


int AJ_Main(int ac, char** av)
{
    AJ_Status status = AJ_OK;
    size_t num = 2;
    size_t i;
    uint8_t b8[sizeof (AJ_Certificate)];
    char pem[1024];
    ecc_privatekey root_prvkey;
    ecc_publickey root_pubkey;
    uint8_t* manifest;
    size_t manifestlen;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    ecc_privatekey peer_prvkey;
    ecc_publickey peer_pubkey;
    AJ_Certificate leaf;
    AJ_Certificate root;
    AJ_GUID guild;

    /*
     * Create an owner key pair
     */
    AJ_GenerateDSAKeyPair(&root_pubkey, &root_prvkey);

    status = AJ_BigEndianEncodePublicKey(&root_pubkey, b8);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_RawToB64(b8, sizeof (ecc_publickey), pem, sizeof (pem));
    AJ_ASSERT(AJ_OK == status);
    AJ_AlwaysPrintf(("Owner Public Key\n"));
    AJ_AlwaysPrintf(("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", pem));

    CreateManifest(&manifest, &manifestlen);
    ManifestDigest(manifest, &manifestlen, digest);

    AJ_RandBytes((uint8_t*) &guild, sizeof (AJ_GUID));

    for (i = 0; i < num; i++) {
        AJ_GenerateDSAKeyPair(&peer_pubkey, &peer_prvkey);

        status = AJ_BigEndianEncodePublicKey(&peer_pubkey, b8);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_RawToB64(b8, sizeof (ecc_publickey), pem, sizeof (pem));
        AJ_ASSERT(AJ_OK == status);
        AJ_AlwaysPrintf(("Peer Public Key\n"));
        AJ_AlwaysPrintf(("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", pem));

        status = AJ_BigEndianEncodePrivateKey(&peer_prvkey, b8);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_RawToB64(b8, sizeof (ecc_privatekey), pem, sizeof (pem));
        AJ_ASSERT(AJ_OK == status);
        AJ_AlwaysPrintf(("Peer Private Key\n"));
        AJ_AlwaysPrintf(("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n", pem));

        status = AJ_CreateCertificate(&leaf, 0, &peer_pubkey, NULL, NULL, digest, 0);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_SignCertificate(&leaf, &peer_prvkey);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_VerifyCertificate(&leaf);
        AJ_ASSERT(AJ_OK == status);

        status = AJ_BigEndianEncodeCertificate(&leaf, b8, sizeof (b8));
        AJ_ASSERT(AJ_OK == status);
        status = AJ_RawToB64(b8, leaf.size, pem, sizeof (pem));
        AJ_ASSERT(AJ_OK == status);
        AJ_AlwaysPrintf(("Peer Certificate (Type 0)\n"));
        AJ_AlwaysPrintf(("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", pem));

        status = AJ_CreateCertificate(&root, 1, &root_pubkey, &peer_pubkey, NULL, digest, 0);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_SignCertificate(&root, &root_prvkey);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_VerifyCertificate(&root);
        AJ_ASSERT(AJ_OK == status);

        status = AJ_BigEndianEncodeCertificate(&root, b8, sizeof (b8));
        AJ_ASSERT(AJ_OK == status);
        status = AJ_RawToB64(b8, root.size, pem, sizeof (pem));
        AJ_ASSERT(AJ_OK == status);
        AJ_AlwaysPrintf(("Root Certificate (Type 1)\n"));
        AJ_AlwaysPrintf(("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", pem));

        status = AJ_CreateCertificate(&root, 2, &root_pubkey, &peer_pubkey, &guild, digest, 0);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_SignCertificate(&root, &root_prvkey);
        AJ_ASSERT(AJ_OK == status);
        status = AJ_VerifyCertificate(&root);
        AJ_ASSERT(AJ_OK == status);

        status = AJ_BigEndianEncodeCertificate(&root, b8, sizeof (b8));
        AJ_ASSERT(AJ_OK == status);
        status = AJ_RawToB64(b8, root.size, pem, sizeof (pem));
        AJ_ASSERT(AJ_OK == status);
        AJ_AlwaysPrintf(("Root Certificate (Type 2)\n"));
        AJ_AlwaysPrintf(("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", pem));
    }

    AJ_Free(manifest);

    return 0;
}

#ifdef AJ_MAIN
int main(int ac, char** av)
{
    return AJ_Main(ac, av);
}
#endif
