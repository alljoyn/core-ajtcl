/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2014-2015, AllSeen Alliance. All rights reserved.
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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE KEYAUTHENTICATION

#include "aj_target.h"
#include "aj_debug.h"
#include "aj_asn1.h"
#include "aj_auth_listener.h"
#include "aj_cert.h"
#include "aj_creds.h"
#include "aj_keyauthentication.h"
#include "aj_peer.h"
#include "aj_x509.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgKEYAUTHENTICATION = 0;
#endif

static AJ_Status ComputeVerifier(const char* label, uint8_t* buffer, size_t bufferlen);

#ifdef AUTH_ECDSA
static AJ_Status ECDSA_Init(AJ_AuthListenerFunc authlistener, const uint8_t* mastersecret, size_t mastersecretlen, AJ_SHA256_Context* hash);
static AJ_Status ECDSA_Marshal(AJ_Message* msg, uint8_t role);
static AJ_Status ECDSA_Unmarshal(AJ_Message* msg, uint8_t role);
static AJ_Status ECDSA_GetIdentity(AJ_Identity* identity, uint32_t* expiration);
static AJ_Status ECDSA_Final();

AJ_KeyAuthentication AJ_KeyAuthenticationECDSA = {
    ECDSA_Init,
    ECDSA_Marshal,
    ECDSA_Unmarshal,
    ECDSA_GetIdentity,
    ECDSA_Final
};

typedef struct _ECDSAContext {
    uint8_t type;
    uint8_t* data;
    size_t size;
} ECDSAContext;
static ECDSAContext ecdsactx;
#endif

#ifdef AUTH_PSK
static AJ_Status PSK_Init(AJ_AuthListenerFunc authlistener, const uint8_t* mastersecret, size_t mastersecretlen, AJ_SHA256_Context* hash);
static AJ_Status PSK_Marshal(AJ_Message* msg, uint8_t role);
static AJ_Status PSK_Unmarshal(AJ_Message* msg, uint8_t role);
static AJ_Status PSK_GetIdentity(AJ_Identity* identity, uint32_t* expiration);
static AJ_Status PSK_Final();

AJ_KeyAuthentication AJ_KeyAuthenticationPSK = {
    PSK_Init,
    PSK_Marshal,
    PSK_Unmarshal,
    PSK_GetIdentity,
    PSK_Final
};

#define AUTH_VERIFIER_LEN SHA256_DIGEST_LENGTH
typedef struct _PSKContext {
    uint8_t* hint;
    size_t hintlen;
    uint8_t* psk;
    size_t psklen;
    AJ_AuthPwdFunc pwdcallback;
} PSKContext;
static PSKContext pskctx;
#endif

#ifdef AUTH_NULL
static AJ_Status NULL_Init(AJ_AuthListenerFunc authlistener, const uint8_t* mastersecret, size_t mastersecretlen, AJ_SHA256_Context* hash);
static AJ_Status NULL_Marshal(AJ_Message* msg, uint8_t role);
static AJ_Status NULL_Unmarshal(AJ_Message* msg, uint8_t role);
static AJ_Status NULL_GetIdentity(AJ_Identity* identity, uint32_t* expiration);
static AJ_Status NULL_Final();

AJ_KeyAuthentication AJ_KeyAuthenticationNULL = {
    NULL_Init,
    NULL_Marshal,
    NULL_Unmarshal,
    NULL_GetIdentity,
    NULL_Final
};
#endif

typedef struct _KeyAuthenticationContext {
    uint8_t* mastersecret;
    size_t mastersecretlen;
    uint32_t expiration;
    AJ_SHA256_Context* hash;
    AJ_AuthListenerFunc authlistener;
} KeyAuthenticationContext;

static KeyAuthenticationContext kactx;

static AJ_Status ComputeVerifier(const char* label, uint8_t* buffer, size_t bufferlen)
{
    AJ_Status status;
    const uint8_t* data[3];
    uint8_t lens[3];
    uint8_t digest[SHA256_DIGEST_LENGTH];

    AJ_SHA256_GetDigest(kactx.hash, digest, 1);

    data[0] = kactx.mastersecret;
    lens[0] = kactx.mastersecretlen;
    data[1] = (uint8_t*) label;
    lens[1] = (uint8_t) strlen(label);
    data[2] = digest;
    lens[2] = sizeof (digest);

    status = AJ_Crypto_PRF_SHA256(data, lens, ArraySize(data), buffer, bufferlen);

    return status;
}

#ifdef AUTH_ECDSA
static AJ_Status ECDSA_Init(AJ_AuthListenerFunc authlistener, const uint8_t* mastersecret, size_t mastersecretlen, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_OK;

    AJ_InfoPrintf(("AJ_ECDSA_Init()\n"));

    /* mastersecret, hash, authlistener will not be NULL */
    kactx.mastersecret = (uint8_t*) mastersecret;
    kactx.mastersecretlen = mastersecretlen;
    kactx.hash = hash;
    kactx.authlistener = authlistener;

    ecdsactx.type = AJ_ID_TYPE_ANY;
    ecdsactx.data = NULL;
    ecdsactx.size = 0;

    return status;
}

static AJ_Status ECDSA_MarshalCertificate(AJ_Message* msg, uint16_t type)
{
    AJ_Status status;
    AJ_CredHead head;
    AJ_CredBody body;

    head.type = type | AJ_CRED_TYPE_CERTIFICATE;
    //TODO use one that matches a TA on the other peer.
    head.id.size = 0;
    head.id.data = NULL;
    status = AJ_GetCredential(&head, &body);
    if (AJ_OK == status) {
        status = AJ_MarshalArgs(msg, "(ay)", body.data.data, body.data.size);
        AJ_SHA256_Update(kactx.hash, body.data.data, body.data.size);
        AJ_CredBodyFree(&body);
    }

    return status;
}

AJ_Status ECDSA_Marshal(AJ_Message* msg, uint8_t role)
{
    AJ_Status status;
    AJ_Arg array1;
    AJ_Arg struct1;
    AJ_KeyInfo prv;
    AJ_SigInfo sig;
    uint8_t verifier[SHA256_DIGEST_LENGTH];
    uint8_t fmt = CERT_FMT_X509_DER;

    AJ_InfoPrintf(("AJ_ECDSA_Marshal(msg=%p)\n", msg));

    if (AUTH_CLIENT == role) {
        status = ComputeVerifier("client finished", verifier, sizeof (verifier));
    } else {
        status = ComputeVerifier("server finished", verifier, sizeof (verifier));
    }
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_ECDSA_Marshal(msg=%p): Compute verifier error\n", msg));
        return AJ_ERR_SECURITY;
    }

    /*
     * Create signature info binding key to verifier
     */
    sig.fmt = SIG_FMT_ALLJOYN;
    sig.alg = SIG_ALG_ECDSA_SHA256;
    status = AJ_KeyInfoGetLocal(&prv, AJ_KEYINFO_ECDSA_SIG_PRV);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Marshal(msg=%p): No signing key available\n", msg));
        return status;
    }
    status = AJ_ECDSASignDigest(verifier, &prv.key.privatekey, &sig.signature);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalVariant(msg, "(yvyv)");
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalContainer(msg, &struct1, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * Marshal signature info
     */
    status = AJ_SigInfoMarshal(&sig, msg, kactx.hash);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Marshal(msg=%p): SigInfo marshal error\n", msg));
        return status;
    }
    status = AJ_MarshalArgs(msg, "y", fmt);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalVariant(msg, "a(ay)");
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalContainer(msg, &array1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    AJ_SHA256_Update(kactx.hash, &fmt, 1);

    /*
     * We only handle sending one certificate at the moment.
     * Our identity certificate.
     */
    status = ECDSA_MarshalCertificate(msg, AJ_CERTIFICATE_IDN_X509_DER);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Marshal(msg=%p): Marshal membership certificate error\n", msg));
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &array1);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &struct1);

    return status;
}

AJ_Status ECDSA_Unmarshal(AJ_Message* msg, uint8_t role)
{
    AJ_Status status;
    AJ_Arg array1;
    AJ_Arg struct1;
    AJ_SHA256_Context ctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    char* variant;
    uint8_t valid = 0;
    uint8_t fmt;
    DER_Element der;
    AJ_KeyInfo pub;
    AJ_SigInfo sig;
    AJ_GUID* issuer;
    X509Certificate certificate;
    ecc_signature* signature;

    AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p)\n", msg));

    if (AUTH_CLIENT == role) {
        status = ComputeVerifier("server finished", digest, sizeof (digest));
    } else {
        status = ComputeVerifier("client finished", digest, sizeof (digest));
    }
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Compute verifier error\n", msg));
        return AJ_ERR_SECURITY;
    }

    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "(yvyv)", 6)) {
        return AJ_ERR_INVALID;
    }

    status = AJ_UnmarshalContainer(msg, &struct1, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * Unmarshal signature info
     */
    status = AJ_SigInfoUnmarshal(&sig, msg, kactx.hash);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Bad SigInfo\n", msg));
        return status;
    }
    issuer = (AJ_GUID*) AJ_GUID_Find(msg->sender);
    signature = &sig.signature;

    status = AJ_UnmarshalArgs(msg, "y", &fmt);
    if (AJ_OK != status) {
        return status;
    }
    if (CERT_FMT_X509_DER != fmt) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): DER encoding expected\n", msg));
        return AJ_ERR_INVALID;
    }
    AJ_SHA256_Update(kactx.hash, &fmt, 1);
    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        return status;
    }
    if (0 != strncmp(variant, "a(ay)", 5)) {
        return AJ_ERR_INVALID;
    }
    status = AJ_UnmarshalContainer(msg, &array1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }

    /*
     * Unmarshal certificate chain - verify as we go
     */
    while (AJ_OK == status) {
        /*
         * Check if we have the public key for the issuer (stored trust anchor).
         * If not, we need to get it from the next certificate in the chain.
         */
        status = AJ_KeyInfoGet(&pub, AJ_KEYINFO_ECDSA_CA_PUB, issuer);
        if (AJ_OK == status) {
            status = AJ_ECDSAVerifyDigest(digest, signature, &pub.key.publickey);
            if (AJ_OK == status) {
                AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate valid\n", msg));
                valid = 1;
                status = AJ_ERR_NO_MORE;
                break;
            }
            /*
             * If not valid, either the signature is incorrect or the stored key is incorrect.
             * We could error here.
             */
        }

        status = AJ_UnmarshalArgs(msg, "(ay)", &der.data, &der.size);
        if (AJ_OK != status) {
            // No more in array
            break;
        }
        AJ_SHA256_Update(kactx.hash, der.data, der.size);
        status = AJ_X509DecodeCertificateDER(&certificate, &der);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate decode failed\n", msg));
            break;
        }

        /*
         * Check subject is previous issuer.
         * Currently, the DN only contains a GUID.
         * If this changes, we need to check the full DN matches.
         */
        if (0 != memcmp(issuer, &certificate.subject, sizeof (AJ_GUID))) {
            AJ_WarnPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate chaining conditions failed\n", msg));
            status = AJ_ERR_SECURITY;
            break;
        }

        /*
         * Get the subject public key and verify previous
         */
        status = AJ_ECDSAVerifyDigest(digest, signature, &certificate.keyinfo.key.publickey);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate invalid\n", msg));
            break;
        }

        /*
         * Update current issuer, digest and signature
         */
        issuer = &certificate.issuer;
        AJ_SHA256_Init(&ctx);
        AJ_SHA256_Update(&ctx, (const uint8_t*) certificate.tbs.data, certificate.tbs.size);
        AJ_SHA256_Final(&ctx, digest);
        signature = &certificate.signature;
        if (!ecdsactx.data) {
            /*
             * This is the bottom certificate
             */
            ecdsactx.type = certificate.type;
            switch (certificate.type) {
            case IDENTITY_CERTIFICATE:
                ecdsactx.size = KEYINFO_PUB_SZ;
                ecdsactx.data = AJ_Malloc(ecdsactx.size);
                if (!ecdsactx.data) {
                    return AJ_ERR_RESOURCES;
                }
                status = AJ_KeyInfoSerialize(&certificate.keyinfo, AJ_KEYINFO_ECDSA_SIG_PUB, ecdsactx.data, ecdsactx.size);
                if (AJ_OK != status) {
                    return status;
                }
                break;

            case MEMBERSHIP_CERTIFICATE:
                ecdsactx.size = sizeof (AJ_GUID);
                ecdsactx.data = AJ_Malloc(ecdsactx.size);
                if (!ecdsactx.data) {
                    return AJ_ERR_RESOURCES;
                }
                memcpy(ecdsactx.data, &certificate.guild, ecdsactx.size);
                break;

            default:
                AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Bad certificate type %x\n", msg, certificate.type));
                return AJ_ERR_SECURITY;
            }
        }
    }
    if (AJ_ERR_NO_MORE != status) {
        AJ_InfoPrintf(("AJ_ECDSA_Unmarshal(msg=%p): Certificate chain error %s\n", msg, AJ_StatusText(status)));
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &array1);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_UnmarshalCloseContainer(msg, &struct1);
    if (AJ_OK != status) {
        return status;
    }

    return valid ? AJ_OK : AJ_ERR_SECURITY;
}

AJ_Status ECDSA_GetIdentity(AJ_Identity* identity, uint32_t* expiration)
{
    identity->level = AJ_SESSION_AUTHENTICATED;
    identity->type = ecdsactx.type;
    identity->data = ecdsactx.data;
    identity->size = ecdsactx.size;
    *expiration = kactx.expiration;
    return AJ_OK;
}

AJ_Status ECDSA_Final()
{
    AJ_InfoPrintf(("AJ_ECDSA_Final()\n"));

    if (ecdsactx.data) {
        AJ_Free(ecdsactx.data);
        ecdsactx.data = NULL;
    }

    return AJ_OK;
}
#endif

#ifdef AUTH_PSK
void AJ_PSK_SetPwdCallback(AJ_AuthPwdFunc pwdcallback)
{
    AJ_InfoPrintf(("AJ_PSK_SetPwdCallback()\n"));
    pskctx.pwdcallback = pwdcallback;
}

static AJ_Status PSK_Init(AJ_AuthListenerFunc authlistener, const uint8_t* mastersecret, size_t mastersecretlen, AJ_SHA256_Context* hash)
{
    AJ_InfoPrintf(("AJ_PSK_Init()\n"));

    /* mastersecret, hash will not be NULL */
    kactx.mastersecret = (uint8_t*) mastersecret;
    kactx.mastersecretlen = mastersecretlen;
    kactx.hash = hash;
    kactx.authlistener = authlistener;

    pskctx.hint = NULL;
    pskctx.hintlen = 0;
    pskctx.psk = NULL;
    pskctx.psklen  = 0;

    return AJ_OK;
}

static AJ_Status PSK_Marshal(AJ_Message* msg, uint8_t role)
{
    AJ_Status status;
    AJ_Credential cred;
    uint8_t verifier[AUTH_VERIFIER_LEN];
    const char* anon = "<anonymous>";

    AJ_InfoPrintf(("AJ_PSK_Marshal(msg=%p)\n", msg));

    if (!pskctx.hint) {
        /*
         * Client to set it.
         */
        status = AJ_ERR_INVALID;
        if (kactx.authlistener) {
            status = kactx.authlistener(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PUB_KEY, &cred);
        }
        if (AJ_OK == status) {
            pskctx.hintlen = cred.len;
            pskctx.hint = (uint8_t*) AJ_Malloc(pskctx.hintlen);
            if (!pskctx.hint) {
                AJ_WarnPrintf(("AJ_PSK_Marshal(msg=%p): AJ_ERR_RESOURCES\n", msg));
                return AJ_ERR_RESOURCES;
            }
            memcpy(pskctx.hint, cred.data, pskctx.hintlen);
        } else {
            /*
             * No hint - use anonymous
             */
            pskctx.hintlen = strlen(anon);
            pskctx.hint = (uint8_t*) AJ_Malloc(pskctx.hintlen);
            if (!pskctx.hint) {
                AJ_WarnPrintf(("AJ_PSK_Marshal(msg=%p): AJ_ERR_RESOURCES\n", msg));
                return AJ_ERR_RESOURCES;
            }
            memcpy(pskctx.hint, anon, pskctx.hintlen);
        }
    }
    cred.mask = AJ_CRED_PUB_KEY;
    cred.data = pskctx.hint;
    cred.len  = pskctx.hintlen;
    if (pskctx.psk) {
        /*
         * Already saved PSK
         */
    } else if (kactx.authlistener) {
        status = kactx.authlistener(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PRV_KEY, &cred);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_PSK_Marshal(msg=%p): No PSK supplied\n", msg));
            return AJ_ERR_SECURITY;
        }
        pskctx.psklen = cred.len;
        pskctx.psk = (uint8_t*) AJ_Malloc(pskctx.psklen);
        if (!pskctx.psk) {
            AJ_WarnPrintf(("AJ_PSK_Marshal(msg=%p): AJ_ERR_RESOURCES\n", msg));
            return AJ_ERR_RESOURCES;
        }
        memcpy(pskctx.psk, cred.data, pskctx.psklen);
        kactx.expiration = cred.expiration;
    } else if (pskctx.pwdcallback) {
        /*
         * Assume application does not copy in more than this size buffer
         * Expiration not set by application
         */
        pskctx.psk = (uint8_t*) AJ_Malloc(16);
        if (!pskctx.psk) {
            AJ_WarnPrintf(("AJ_PSK_Marshal(msg=%p): AJ_ERR_RESOURCES\n", msg));
            return AJ_ERR_RESOURCES;
        }
        pskctx.psklen = pskctx.pwdcallback(pskctx.psk, 16);
        kactx.expiration = 0xFFFFFFFF;
    } else {
        AJ_WarnPrintf(("AJ_PSK_Marshal(msg=%p): No PSK supplied\n", msg));
        return AJ_ERR_SECURITY;
    }

    if (AUTH_CLIENT == role) {
        AJ_SHA256_Update(kactx.hash, pskctx.hint, pskctx.hintlen);
        AJ_SHA256_Update(kactx.hash, pskctx.psk, pskctx.psklen);
        status = ComputeVerifier("client finished", verifier, sizeof (verifier));
        AJ_SHA256_Update(kactx.hash, verifier, sizeof (verifier));
    } else {
        status = ComputeVerifier("server finished", verifier, sizeof (verifier));
    }
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PSK_Marshal(msg=%p): Compute verifier error\n", msg));
        return AJ_ERR_SECURITY;
    }
    status = AJ_MarshalVariant(msg, "(ayay)");
    status = AJ_MarshalArgs(msg, "(ayay)", pskctx.hint, pskctx.hintlen, verifier, sizeof (verifier));

    return status;
}

static AJ_Status PSK_Unmarshal(AJ_Message* msg, uint8_t role)
{
    AJ_Status status;
    AJ_Credential cred;
    char* variant;
    uint8_t verifier[AUTH_VERIFIER_LEN];
    uint8_t* remotehint;
    uint8_t* remotesig;
    size_t remotehintlen;
    size_t remotesiglen;

    AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p)\n", msg));

    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p): Unmarshal variant error\n", msg));
        return AJ_ERR_SECURITY;
    }
    if (0 != strncmp(variant, "(ayay)", 6)) {
        AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p): Invalid variant\n", msg));
        return AJ_ERR_SECURITY;
    }
    status = AJ_UnmarshalArgs(msg, "(ayay)", &remotehint, &remotehintlen, &remotesig, &remotesiglen);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p): Unmarshal error\n", msg));
        return AJ_ERR_SECURITY;
    }
    if (AUTH_VERIFIER_LEN != remotesiglen) {
        AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p): Invalid signature size\n", msg));
        return AJ_ERR_SECURITY;
    }

    if (pskctx.hint) {
        if (pskctx.hintlen != remotehintlen) {
            AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p): Invalid hint size\n", msg));
            return AJ_ERR_SECURITY;
        }
        if (0 != memcmp(pskctx.hint, remotehint, pskctx.hintlen)) {
            AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p): Invalid hint\n", msg));
            return AJ_ERR_SECURITY;
        }
    } else {
        pskctx.hintlen = remotehintlen;
        pskctx.hint = (uint8_t*) AJ_Malloc(pskctx.hintlen);
        if (!pskctx.hint) {
            AJ_WarnPrintf(("AJ_PSK_Unmarshal(msg=%p): AJ_ERR_RESOURCES\n", msg));
            return AJ_ERR_RESOURCES;
        }
        memcpy(pskctx.hint, remotehint, pskctx.hintlen);
    }
    if (pskctx.psk) {
        /*
         * Already saved PSK
         */
    } else if (kactx.authlistener) {
        cred.mask = AJ_CRED_PUB_KEY;
        cred.data = pskctx.hint;
        cred.len  = pskctx.hintlen;
        status = kactx.authlistener(AUTH_SUITE_ECDHE_PSK, AJ_CRED_PRV_KEY, &cred);
        if (AJ_OK != status) {
            AJ_WarnPrintf(("AJ_PSK_Unmarshal(msg=%p): No PSK supplied\n", msg));
            return AJ_ERR_SECURITY;
        }
        pskctx.psklen = cred.len;
        pskctx.psk = (uint8_t*) AJ_Malloc(pskctx.psklen);
        if (!pskctx.psk) {
            AJ_WarnPrintf(("AJ_PSK_Unmarshal(msg=%p): AJ_ERR_RESOURCES\n", msg));
            return AJ_ERR_RESOURCES;
        }
        memcpy(pskctx.psk, cred.data, pskctx.psklen);
        kactx.expiration = cred.expiration;
    } else if (pskctx.pwdcallback) {
        /*
         * Assume application does not copy in more than this size buffer
         * Expiration not set by application
         */
        pskctx.psk = (uint8_t*) AJ_Malloc(16);
        if (!pskctx.psk) {
            AJ_WarnPrintf(("AJ_PSK_Unmarshal(msg=%p): AJ_ERR_RESOURCES\n", msg));
            return AJ_ERR_RESOURCES;
        }
        pskctx.psklen = pskctx.pwdcallback(pskctx.psk, 16);
        kactx.expiration = 0xFFFFFFFF;
    } else {
        AJ_WarnPrintf(("AJ_PSK_Unmarshal(msg=%p): No PSK supplied\n", msg));
        return AJ_ERR_SECURITY;
    }

    if (AUTH_CLIENT == role) {
        status = ComputeVerifier("server finished", verifier, sizeof (verifier));
    } else {
        AJ_SHA256_Update(kactx.hash, pskctx.hint, pskctx.hintlen);
        AJ_SHA256_Update(kactx.hash, pskctx.psk, pskctx.psklen);
        status = ComputeVerifier("client finished", verifier, sizeof (verifier));
        AJ_SHA256_Update(kactx.hash, verifier, sizeof (verifier));
    }
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PSK_Unmarshal(msg=%p): Compute verifier error\n", msg));
        return AJ_ERR_SECURITY;
    }
    if (0 != memcmp(verifier, remotesig, AUTH_VERIFIER_LEN)) {
        AJ_InfoPrintf(("AJ_PSK_Unmarshal(msg=%p): Invalid verifier\n", msg));
        return AJ_ERR_SECURITY;
    }

    return status;
}

AJ_Status PSK_GetIdentity(AJ_Identity* identity, uint32_t* expiration)
{
    identity->level = AJ_SESSION_AUTHENTICATED;
    //We have not defined PSK identities in policy yet
    identity->type = AJ_ID_TYPE_ANY;
    identity->data = pskctx.hint;
    identity->size = pskctx.hintlen;
    *expiration = kactx.expiration;
    return AJ_OK;
}

AJ_Status PSK_Final()
{
    AJ_InfoPrintf(("AJ_PSK_Final()\n"));

    if (pskctx.hint) {
        AJ_Free(pskctx.hint);
        pskctx.hint = NULL;
    }
    if (pskctx.psk) {
        AJ_Free(pskctx.psk);
        pskctx.psk  = NULL;
    }

    return AJ_OK;
}
#endif

#ifdef AUTH_NULL
static AJ_Status NULL_Init(AJ_AuthListenerFunc authlistener, const uint8_t* mastersecret, size_t mastersecretlen, AJ_SHA256_Context* hash)
{
    AJ_Status status = AJ_OK;
    AJ_Credential cred;

    AJ_InfoPrintf(("AJ_NULL_Init()\n"));

    /* mastersecret, hash will not be NULL */
    kactx.mastersecret = (uint8_t*) mastersecret;
    kactx.mastersecretlen = mastersecretlen;
    kactx.hash = hash;
    kactx.expiration = 0;
    if (authlistener) {
        status = authlistener(AUTH_SUITE_ECDHE_NULL, 0, &cred);
        if (AJ_OK == status) {
            kactx.expiration = cred.expiration;
        }
    }

    return AJ_OK;
}

static AJ_Status NULL_Marshal(AJ_Message* msg, uint8_t role)
{
    AJ_Status status;
    uint8_t verifier[AUTH_VERIFIER_LEN];

    AJ_InfoPrintf(("AJ_NULL_Marshal(msg=%p)\n", msg));

    if (AUTH_CLIENT == role) {
        status = ComputeVerifier("client finished", verifier, sizeof (verifier));
    } else {
        status = ComputeVerifier("server finished", verifier, sizeof (verifier));
    }
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_NULL_Marshal(msg=%p): Compute verifier error\n", msg));
        return AJ_ERR_SECURITY;
    }
    status = AJ_MarshalVariant(msg, "ay");
    status = AJ_MarshalArgs(msg, "ay", verifier, sizeof (verifier));
    AJ_SHA256_Update(kactx.hash, verifier, sizeof (verifier));

    return status;
}

static AJ_Status NULL_Unmarshal(AJ_Message* msg, uint8_t role)
{
    AJ_Status status;
    char* variant;
    uint8_t verifier[AUTH_VERIFIER_LEN];
    uint8_t* remotesig;
    size_t remotesiglen;

    AJ_InfoPrintf(("AJ_NULL_Unmarshal(msg=%p)\n", msg));

    if (AUTH_CLIENT == role) {
        status = ComputeVerifier("server finished", verifier, sizeof (verifier));
    } else {
        status = ComputeVerifier("client finished", verifier, sizeof (verifier));
    }
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_NULL_Unmarshal(msg=%p): Compute verifier error\n", msg));
        return AJ_ERR_SECURITY;
    }

    status = AJ_UnmarshalVariant(msg, (const char**) &variant);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_NULL_Unmarshal(msg=%p): Unmarshal variant error\n", msg));
        return AJ_ERR_SECURITY;
    }
    if (0 != strncmp(variant, "ay", 4)) {
        AJ_InfoPrintf(("AJ_NULL_Unmarshal(msg=%p): Invalid variant\n", msg));
        return AJ_ERR_SECURITY;
    }
    status = AJ_UnmarshalArgs(msg, "ay", &remotesig, &remotesiglen);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_NULL_Unmarshal(msg=%p): Unmarshal error\n", msg));
        return AJ_ERR_SECURITY;
    }
    if (AUTH_VERIFIER_LEN != remotesiglen) {
        AJ_InfoPrintf(("AJ_NULL_Unmarshal(msg=%p): Invalid signature size\n", msg));
        return AJ_ERR_SECURITY;
    }
    if (0 != memcmp(verifier, remotesig, AUTH_VERIFIER_LEN)) {
        AJ_InfoPrintf(("AJ_NULL_Unmarshal(msg=%p): Invalid verifier\n", msg));
        return AJ_ERR_SECURITY;
    }
    AJ_SHA256_Update(kactx.hash, verifier, sizeof (verifier));

    return status;
}

AJ_Status NULL_GetIdentity(AJ_Identity* identity, uint32_t* expiration)
{
    identity->level = AJ_SESSION_ENCRYPTED;
    identity->type = AJ_ID_TYPE_ANY;
    identity->data = NULL;
    identity->size = 0;
    *expiration = kactx.expiration;
    return AJ_OK;
}

AJ_Status NULL_Final()
{
    AJ_InfoPrintf(("AJ_NULL_Final()\n"));

    return AJ_OK;
}
#endif
