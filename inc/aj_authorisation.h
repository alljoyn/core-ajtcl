#ifndef _AJ_AUTHORISATION_H
#define _AJ_AUTHORISATION_H
/**
 * @file aj_authorisation.h
 * @defgroup aj_authorisation Authorisation Support
 * @{
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

#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_introspect.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_crypto_sha2.h>
#include <ajtcl/aj_guid.h>
#include <ajtcl/aj_msg.h>
#include <ajtcl/aj_target.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AJ_ACCESS_INCOMING           0x1
#define AJ_ACCESS_OUTGOING           0x2

#define AJ_MEMBER_TYPE_ANY             0
#define AJ_MEMBER_TYPE_METHOD          1
#define AJ_MEMBER_TYPE_SIGNAL          2
#define AJ_MEMBER_TYPE_PROPERTY        3
#define AJ_ACTION_PROVIDE            0x1
#define AJ_ACTION_OBSERVE            0x2
#define AJ_ACTION_MODIFY             0x4
typedef struct _AJ_PermissionMember {
    const char* mbr;                   /**< Member name */
    uint8_t type;                      /**< Member type (METHOD, SIGNAL, etc.) */
    uint8_t action;                    /**< Action (PROVIDE, OBSERVE, etc.) */
    struct _AJ_PermissionMember* next;
} AJ_PermissionMember;

typedef struct _AJ_PermissionRule {
    const char* obj;                   /**< Object name */
    const char* ifn;                   /**< Interface name */
    AJ_PermissionMember* members;      /**< Members */
    struct _AJ_PermissionRule* next;
} AJ_PermissionRule;

typedef struct _AJ_Manifest {
    uint32_t version;                  /**< Version */
    AJ_PermissionRule* rules;          /**< Rules */
    const char* thumbprintAlgorithmOid;/**< Thumbprint algorithm OID */
    uint8_t* thumbprint;               /**< Identity certificate thumbprint */
    uint32_t thumbprintSize;           /**< Length of identity certificate thumbprint */
    const char* signatureAlgorithmOid; /**< Signature algorithm OID */
    uint8_t* signature;                /**< Signature */
    uint32_t signatureSize;            /**< Length of signature */
    uint16_t serializedSize;           /**< Size of serialized form */
} AJ_Manifest;

typedef struct _AJ_ManifestArray {
    AJ_Manifest* manifest;             /**< Manifests */
    struct _AJ_ManifestArray* next;
} AJ_ManifestArray;

#define AJ_PEER_TYPE_ALL               0
#define AJ_PEER_TYPE_ANY_TRUSTED       1
#define AJ_PEER_TYPE_FROM_CA           2
#define AJ_PEER_TYPE_WITH_PUBLIC_KEY   3
#define AJ_PEER_TYPE_WITH_MEMBERSHIP   4
typedef struct _AJ_PermissionPeer {
    uint8_t type;                      /**< Peer type */
    DER_Element kid;                   /**< Key identifier (optional) */
    AJ_ECCPublicKey pub;               /**< ECC public key (optional) */
    DER_Element group;                 /**< Group identifier (optional) */
    struct _AJ_PermissionPeer* next;
} AJ_PermissionPeer;

typedef struct _AJ_PermissionACL {
    AJ_PermissionPeer* peers;          /**< Peers */
    AJ_PermissionRule* rules;          /**< Rules */
    struct _AJ_PermissionACL* next;
} AJ_PermissionACL;

typedef struct _AJ_Policy {
    uint16_t specification;            /**< Specification version */
    uint32_t version;                  /**< Policy version */
    AJ_PermissionACL* acls;            /**< ACLs */
} AJ_Policy;

/**
 * Register objects on the access control list
 *
 * @param list         The object list
 * @param l            The std, app, prx identifier
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_RESOURCES if memory not available
 */
AJ_Status AJ_AuthorisationRegister(const AJ_Object* list, uint8_t l);

/**
 * Cleanup access control memory
 */
void AJ_AuthorisationClose(void);

/**
 * Set the manifest template, called by the application
 *
 * @param manifest     The manifest
 */
void AJ_ManifestTemplateSet(AJ_PermissionRule* manifest);

/**
 * Marshal the manifest template, set from the application
 *
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestTemplateMarshal(AJ_Message* msg);

/**
 * Calculate manifest digest
 *
 * @param manifest     The marshalled manifest message body
 * @param digest       The output digest
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_RESOURCES or AJ_ERR_SECURITY if the digest failed
 */
AJ_Status AJ_ManifestDigest(AJ_CredField * manifest, uint8_t digest[AJ_SHA256_DIGEST_LENGTH]);

/**
 * Marshal a manifest record. The signature field can optionally be omitted for the purposes
 * of computing the manifest's digest.
 *
 * @param manifest         The manifest
 * @param msg              The outgoing message
 * @param useForDigest     TRUE to exclude the signature field for purposes of computing a digest
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestMarshal(AJ_Manifest* manifest, AJ_Message* msg, uint8_t useForDigest);

/**
 * Unmarshal a manifest record
 *
 * @param manifest     The manifest
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestUnmarshal(AJ_Manifest** manifest, AJ_Message* msg);

/**
 * Marshal a manifest array
 *
 * @param manifest     The manifest array
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestArrayMarshal(AJ_ManifestArray* manifests, AJ_Message* msg);

/**
 * Unmarshal a manifest array
 *
 * @param manifests    The manifest array
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestArrayUnmarshal(AJ_ManifestArray** manifests, AJ_Message* msg);


/**
 * Marshal a policy record
 *
 * @param policy       The policy
 * @param msg          The outgoing message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyMarshal(const AJ_Policy* policy, AJ_Message* msg);

/**
 * Unmarshal a policy record
 *
 * @param policy       The policy
 * @param msg          The incoming message
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyUnmarshal(AJ_Policy** policy, AJ_Message* msg);

/**
 * Free manifest memory
 *
 * @param manifest     The manifest object
 */
void AJ_ManifestFree(AJ_Manifest* manifest);

/**
 * Free manifest array memory
 *
 * @param manifests    The manifest array
 */
void AJ_ManifestArrayFree(AJ_ManifestArray* manifests);

/**
 * Free policy memory
 *
 * @param policy       The policy object
 */
void AJ_PolicyFree(AJ_Policy* policy);

/**
 * Marshal the default policy
 *
 * @param field        The local buffer.
 * @param ca           The CA peer
 * @param admin        The Admin group peer
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_MarshalDefaultPolicy(AJ_CredField* field, AJ_PermissionPeer* peer_ca, AJ_PermissionPeer* peer_admin);

/**
 * Apply the manifest access rules
 *
 * @param manifest     The manifest object
 * @param name         The peer's name
 * @param ctx          The authentication context
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_ACCESS if the named peer is not found
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_ManifestApply(AJ_Manifest* manifest, const char* name, AJ_AuthenticationContext* ctx);

/**
 * Validate and apply an array of manifests
 *
 * @param manifests    The array of manifests
 * @param name         The peer's name
 * @param ctx          The authentication context
 *
 */
void AJ_ManifestArrayApply(AJ_ManifestArray* manifests, const char* name, AJ_AuthenticationContext* ctx);

/**
 * Apply the policy access rules
 *
 * @param ctx          The authentication context
 * @param name         The peer's name
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyApply(AJ_AuthenticationContext* ctx, const char* name);

/**
 * Apply the policy access rules for a group membership
 *
 * @param root         The membership certificate chain
 * @param issuer       The root certificate authority
 * @param group        The membership group
 * @param name         The peer's name
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_MembershipApply(X509CertificateChain* root, AJ_ECCPublicKey* issuer, DER_Element* group, const char* name);

/**
 * Get the policy version
 *
 * @param version      The output policy version
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_PolicyVersion(uint32_t* version);

/**
 * Search for the intermediate issuers amongst the stored authorities
 *
 * @param root         The certificate chain
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_PolicyFindAuthority(const X509CertificateChain* root);

/**
 * Attempt to verify certificate using stored authorities
 *
 * @param cert         The certificate
 * @param pub          The output public key
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY otherwise
 */
AJ_Status AJ_PolicyVerifyCertificate(const X509Certificate* cert, AJ_ECCPublicKey* pub);

/**
 * Access control check for message
 *
 * @param msg          The message
 * @param name         The peer's name
 * @param direction    The message direction (incoming/outgoing)
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_ACCESS on all failures
 */
AJ_Status AJ_AccessControlCheckMessage(const AJ_Message* msg, const char* name, uint8_t direction);

/**
 * Access control check for a property
 *
 * @param msg          The message
 * @param id           The property id
 * @param name         The peer's name
 * @param direction    The message direction (incoming/outgoing)
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_ACCESS on all failures
 */
AJ_Status AJ_AccessControlCheckProperty(const AJ_Message* msg, uint32_t id, const char* name, uint8_t direction);

/**
 * Reset access control list for a peer
 *
 * @param name         The peer's name
 *
 * @return
 *          - AJ_OK on success
 *          - AJ_ERR_INVALID otherwise
 */
AJ_Status AJ_AccessControlReset(const char* name);

/**
 * Marshal a manifest to a local buffer.
 *
 * @param manifest         The input manifest.
 * @param field            The local buffer.
 * @param useForDigest     TRUE to exclude the signature field for purposes of computing a digest
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_ManifestToBuffer(AJ_Manifest* manifest, AJ_CredField* field, uint8_t useForDigest);

/**
 * Unmarshal a manifest from a local buffer.
 *
 * @param manifest     The output manifest.
 * @param field        The local buffer.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_ManifestFromBuffer(AJ_Manifest** manifest, AJ_CredField* field);

/**
 * Marshal a manifest array to a local buffer.
 *
 * @param manifests    The input manifest array.
 * @param field        The local buffer.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_ManifestArrayToBuffer(AJ_ManifestArray* manifest, AJ_CredField* field);

/**
 * Unmarshal a manifest array from a local buffer.
 *
 * @param manifests    The output manifest array.
 * @param field        The local buffer.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_ManifestArrayFromBuffer(AJ_ManifestArray** manifest, AJ_CredField* field);

/**
 * Marshal a policy to a local buffer.
 *
 * @param policy       The input policy.
 * @param field        The local buffer.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_PolicyToBuffer(AJ_Policy* policy, AJ_CredField* field);

/**
 * Unmarshal a policy from a local buffer.
 *
 * @param policy       The output policy.
 * @param field        The local buffer.
 *
 * @return  Return AJ_Status
 *          - AJ_OK on success
 *          - AJ_ERR_SECURITY on failure
 */
AJ_Status AJ_PolicyFromBuffer(AJ_Policy** policy, AJ_CredField* field);

/**
 * Checks if name is a substring of a description,
 * also allows wildcard matching.
 *
 * @param name         The name of access control element
 * @param desc         The description (object, interface, member)
 * @param type         The description type (SIGNAL, METHOD, PROPERTY)
 *
 * @return  Return uint8_t
 *          - 1 on success
 *          - 0 on failure
 */
uint8_t AJ_CommonPath(const char* name, const char* desc, uint8_t type);

/*
 * Load policy into memory
 */
AJ_Status AJ_PolicyLoad(void);

/*
 * Unload policy from memory
 */
void AJ_PolicyUnload(void);

/**
 * Determine if a manifest has been signed by looking for the presence of the thumbprint and
 * signature fields. This does not verify the cryptographic signature, as that requires access
 * to the public key of the signer which may not be available. Instead, this allows rejecting
 * unsigned manifests which can never be valid.
 *
 * @param manifest     The manifest to check
 *
 * @return   Return uint8_t
 *           - TRUE if fields have been set that indicate signature
 *           - FALSE otherwise
 */
uint8_t AJ_ManifestHasSignature(const AJ_Manifest* manifest);

/**
 * Filter out any unsigned manifests from an array.
 *
 * @param manifests    Pointer to a pointer to linked list. Because the first element might be filtered,
 *                     this might be changed.
 */
void AJ_ManifestArrayFilterUnsigned(AJ_ManifestArray** manifests);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif
