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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE AUTHORISATION

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_authorisation.h>
#include <ajtcl/aj_std.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_peer.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_guid.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_security.h>
#include <ajtcl/aj_msg_priv.h>

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgAUTHORISATION = 0;
#endif

#define POLICY_SPECIFICATION_VERSION   1

/**
 * Constants for some message argument signatures.
 */
static const char* s_ManifestMsgArgSignature = "(ua(ssa(syy))saysay)";
static const char* s_ManifestMsgArgDigestSignature = "(ua(ssa(syy))says)";
static const char* s_ManifestArrayMsgArgSignature = "a(ua(ssa(syy))saysay)";

/*
 * Policy helper struct.
 * Contains a buffer of the raw marshalled data,
 * and an AJ_Policy struct referencing inside the buffer.
 */
typedef struct _Policy {
    AJ_CredField buffer;
    AJ_Policy* policy;
} Policy;
Policy g_policy = { { 0, NULL }, NULL };

#define POLICY_METHOD_INCOMING      0x01
#define POLICY_METHOD_OUTGOING      0x02
#define POLICY_PRPSET_INCOMING      0x04
#define POLICY_PRPSET_OUTGOING      0x08
#define POLICY_SIGNAL_INCOMING      POLICY_METHOD_INCOMING
#define POLICY_SIGNAL_OUTGOING      POLICY_METHOD_OUTGOING
#define POLICY_PRPGET_INCOMING      POLICY_METHOD_INCOMING
#define POLICY_PRPGET_OUTGOING      POLICY_METHOD_OUTGOING
#define POLICY_PRPALL_INCOMING      POLICY_METHOD_INCOMING
#define POLICY_PRPALL_OUTGOING      POLICY_METHOD_OUTGOING
#define MANIFEST_METHOD_INCOMING    (POLICY_METHOD_INCOMING << 4)
#define MANIFEST_METHOD_OUTGOING    (POLICY_METHOD_OUTGOING << 4)
#define MANIFEST_PRPSET_INCOMING    (POLICY_PRPSET_INCOMING << 4)
#define MANIFEST_PRPSET_OUTGOING    (POLICY_PRPSET_OUTGOING << 4)
#define MANIFEST_SIGNAL_INCOMING    MANIFEST_METHOD_INCOMING
#define MANIFEST_SIGNAL_OUTGOING    MANIFEST_METHOD_OUTGOING
#define MANIFEST_PRPGET_INCOMING    MANIFEST_METHOD_INCOMING
#define MANIFEST_PRPGET_OUTGOING    MANIFEST_METHOD_OUTGOING
#define MANIFEST_PRPALL_INCOMING    MANIFEST_METHOD_INCOMING
#define MANIFEST_PRPALL_OUTGOING    MANIFEST_METHOD_OUTGOING
#define POLICY_INCOMING             (POLICY_METHOD_INCOMING | POLICY_PRPSET_INCOMING)
#define POLICY_OUTGOING             (POLICY_METHOD_OUTGOING | POLICY_PRPSET_OUTGOING)
#define MANIFEST_INCOMING           (MANIFEST_METHOD_INCOMING | MANIFEST_PRPSET_INCOMING)
#define MANIFEST_OUTGOING           (MANIFEST_METHOD_OUTGOING | MANIFEST_PRPSET_OUTGOING)
#define POLICY_ACCESS               (POLICY_INCOMING | POLICY_OUTGOING)
#define MANIFEST_ACCESS             (MANIFEST_INCOMING | MANIFEST_OUTGOING)

/*
 * The main access control structure.
 * Maps message ids to peer's access.
 */
typedef struct _AccessControlMember {
    uint32_t id;
    const char* obj;
    const char* ifn;
    const char* mbr;
    uint8_t deny[AJ_NAME_MAP_GUID_SIZE];
    uint8_t allow[AJ_NAME_MAP_GUID_SIZE];
    struct _AccessControlMember* next;
} AccessControlMember;

static AJ_PermissionRule* g_manifestRules = NULL;
static AccessControlMember* g_access = NULL;

static void AccessControlClose(void)
{
    AccessControlMember* member;

    while (g_access) {
        member = g_access;
        g_access = g_access->next;
        AJ_Free(member);
    }
}

/*
 * Iterates through all object/interface descriptions
 * and saves the names and ids for each secure member.
 * The object, interface and member names are used when
 * applying policy.
 * The member id is used when applying access control
 * for each incoming or outgoing message.
 */
static AJ_Status AccessControlRegister(const AJ_Object* list, uint8_t l)
{
    const AJ_Object* obj;
    const AJ_InterfaceDescription* interfaces;
    AJ_InterfaceDescription iface;
    const char* ifn;
    const char* mbr;
    uint8_t secure;
    uint8_t i, m;
    uint16_t n = 0;
    AccessControlMember* member;
    uint32_t properties;

    AJ_InfoPrintf(("AccessControlRegister(list=%p, l=%x)\n", list, l));

    if (NULL == list) {
        /* Nothing to add to the list */
        return AJ_OK;
    }

    while (list[n].path) {
        obj = &list[n++];
        interfaces = obj->interfaces;
        if (!interfaces) {
            continue;
        }
        i = 0;
        properties = FALSE;
        while (*interfaces) {
            iface = *interfaces++;
            ifn = *iface++;
            AJ_ASSERT(ifn);
            secure = obj->flags & AJ_OBJ_FLAG_SECURE;
            secure |= (SECURE_TRUE == *ifn);
            secure &= ~(SECURE_OFF == *ifn);
            /* Only access control secure objects/interfaces */
            if (secure) {
                m = 0;
                while (*iface) {
                    mbr = *iface++;
                    member = (AccessControlMember*) AJ_Malloc(sizeof (AccessControlMember));
                    if (NULL == member) {
                        AJ_WarnPrintf(("AccessControlRegister(list=%p, l=%x): AJ_ERR_RESOURCES\n", list, l));
                        goto Exit;
                    }
                    memset(member, 0, sizeof (AccessControlMember));
                    member->obj = obj->path;
                    member->ifn = ifn;
                    member->mbr = mbr;
                    member->id = AJ_ENCODE_MESSAGE_ID(l, n - 1, i, m);
                    member->next = g_access;
                    g_access = member;
                    properties |= (PROPERTY == MEMBER_TYPE(*mbr));
                    AJ_InfoPrintf(("AccessControlRegister: id 0x%08X obj %s ifn %s mbr %s\n", member->id, obj->path, ifn, mbr));
                    m++;
                }
                if (properties) {
                    /* Add special member to handle DBus.Properties GetAll method */
                    member = (AccessControlMember*) AJ_Malloc(sizeof (AccessControlMember));
                    if (NULL == member) {
                        AJ_WarnPrintf(("AccessControlRegister(list=%p, l=%x): AJ_ERR_RESOURCES\n", list, l));
                        goto Exit;
                    }
                    memset(member, 0, sizeof (AccessControlMember));
                    member->obj = obj->path;
                    member->ifn = ifn;
                    /* Setting the member to "@" will match an PROPERTY with wildcard for member name */
                    member->mbr = "@";
                    member->id = AJ_INVALID_MSG_ID;
                    member->next = g_access;
                    g_access = member;
                    AJ_InfoPrintf(("AccessControlRegister: id 0x%08X obj %s ifn %s mbr %s\n", member->id, obj->path, ifn, member->mbr));
                }
            }
            i++;
        }
    }

    return AJ_OK;

Exit:
    return AJ_ERR_RESOURCES;
}

static void AccessControlDeregister(uint8_t l)
{
    AccessControlMember* node;
    AccessControlMember* head = g_access;

    /* Remove nodes from beginning of the list */
    while (NULL != head) {
        if (l == (head->id >> 24)) {
            AJ_InfoPrintf(("AccessControlDeregister: id 0x%08X obj %s ifn %s mbr %s\n", head->id, head->obj, head->ifn, head->mbr));
            node = head;
            head = head->next;
            AJ_Free(node);
        } else {
            break;
        }
    }
    g_access = head;
    if (NULL == g_access) {
        return;
    }
    /* Remove nodes from rest of the list */
    while (NULL != head->next) {
        if (l == (head->next->id >> 24)) {
            AJ_InfoPrintf(("AccessControlDeregister: id 0x%08X obj %s ifn %s mbr %s\n", head->next->id, head->next->obj, head->next->ifn, head->next->mbr));
            node = head->next;
            head->next = node->next;
            AJ_Free(node);
        } else {
            head = head->next;
        }
    }
}

static AccessControlMember* FindAccessControlMember(uint32_t id)
{
    AccessControlMember* mbr;

    if (!g_access) {
        AJ_WarnPrintf(("FindAccessControlMember(id=0x%08X): Access table not initialised\n", id));
        return NULL;
    }

    // This linked list is a reverse ordered list
    mbr = g_access;
    while (mbr && (id != mbr->id)) {
        mbr = mbr->next;
    }

    return mbr;
}

static uint32_t IsInterface(const char* std, const char* ifn)
{
    const char* s = std;

    AJ_ASSERT(std);
    AJ_ASSERT(ifn);
    if (SECURE_OFF == *std) {
        s++;
    }
    return (0 == strcmp(s, ifn));
}

static uint32_t PropertiesInterface(const char* ifn)
{
    return IsInterface(AJ_PropertiesIface[0], ifn);
}

static uint32_t StandardInterface(const char* ifn)
{
    /*
     * We could include all the standard interfaces.
     * Currently we only expect encrypted messages
     * on org.alljoyn.Bus.Peer.Authentication
     */
    return IsInterface(PeerAuthInterface, ifn);
}

static AccessControlMember* FindGetAllMember(const void* buf, size_t len)
{
    AccessControlMember* acm = g_access;
    const char* ifn;

    while (acm) {
        ifn = acm->ifn;
        /* Skip over secure annotation */
        if ((SECURE_TRUE == *ifn) || (SECURE_OFF == *ifn)) {
            ifn++;
        }
        if ((AJ_INVALID_MSG_ID == acm->id) && (len == strlen(ifn) && (0 == AJ_Crypto_Compare(buf, acm->ifn, len)))) {
            /* Same interface */
            return acm;
        }
        acm = acm->next;
    }

    return NULL;
}

static AJ_Status PropertiesInterfaceCheck(const AJ_Message* msg, uint8_t direction, uint32_t peer)
{
    AccessControlMember* acm;
    uint8_t* buf;
    uint32_t len;
    uint8_t acc;

    AJ_InfoPrintf(("PropertiesInterfaceCheck(msg=%p, direction=%x, peer=%d): 0x%08X\n", msg, direction, peer, msg->msgId));
    /* All incoming calls are handled when marshalling/unmarshalling the property id */
    if (AJ_ACCESS_INCOMING == direction) {
        return AJ_OK;
    }
    /* Get and Set outgoing are handled when marshalling/unmarshalling the property id */
    if ((AJ_PROP_GET == (msg->msgId & 0xFF)) || (AJ_PROP_SET == (msg->msgId & 0xFF))) {
        return AJ_OK;
    }
    /*
     * Get the target interface from the message body.
     */
    buf = msg->bus->sock.tx.bufStart + sizeof(AJ_MsgHeader) + msg->hdr->headerLen + HEADERPAD(msg->hdr->headerLen);
    len = *(uint32_t*) buf;
    buf += sizeof (uint32_t);
    acm = FindGetAllMember(buf, len);
    if (acm) {
        acc = acm->deny[peer] ? 0 : acm->allow[peer];
        if ((POLICY_PRPALL_OUTGOING & acc) && (MANIFEST_PRPALL_OUTGOING & acc)) {
            return AJ_OK;
        }
    }
    acm = acm->next;

    return AJ_ERR_ACCESS;
}

AJ_Status AJ_AccessControlCheckMessage(const AJ_Message* msg, const char* name, uint8_t direction)
{
    AJ_Status status;
    AccessControlMember* mbr;
    uint32_t peer;
    uint8_t acc;

    AJ_InfoPrintf(("AJ_AccessControlCheckMessage(msg=%p, name=%s, direction=%x): Obj %s Ifn %s Mbr %s\n", msg, name, direction, msg->objPath, msg->iface, msg->member));

    /*
     * We may get encrypted messages on "unsecured" interfaces.
     * org.freedesktop.DBus.Properties
     * org.alljoyn.Bus.Peer.Authentication
     */
    if (StandardInterface(msg->iface)) {
        AJ_InfoPrintf(("AJ_AccessControlCheckMessage(msg=%p, name=%s, direction=%x): AJ_OK\n", msg, name, direction));
        return AJ_OK;
    }

    /* Check Peer.Authentication before this because we don't have a peer entry yet */
    status = AJ_GetPeerIndex(name, &peer);
    if (AJ_OK != status) {
        return AJ_ERR_ACCESS;
    }

    if (PropertiesInterface(msg->iface)) {
        status = PropertiesInterfaceCheck(msg, direction, peer);
        AJ_InfoPrintf(("AJ_AccessControlCheckMessage(msg=%p, name=%s, direction=%x): %s\n", msg, name, direction, AJ_StatusText(status)));
        return status;
    }

    mbr = FindAccessControlMember(msg->msgId);
    if (NULL == mbr) {
        AJ_WarnPrintf(("AJ_AccessControlCheckMessage(msg=%p, name=%s, direction=%x): Member 0x%08X not in table AJ_ERR_ACCESS\n", msg, name, direction, msg->msgId));
        return AJ_ERR_ACCESS;
    }

    status = AJ_ERR_ACCESS;
    acc = mbr->deny[peer] ? 0 : mbr->allow[peer];
    switch (direction) {
    case AJ_ACCESS_INCOMING:
        if ((POLICY_METHOD_INCOMING & acc) && (MANIFEST_METHOD_INCOMING & acc)) {
            status = AJ_OK;
        }
        break;

    case AJ_ACCESS_OUTGOING:
        if ((POLICY_METHOD_OUTGOING & acc) && (MANIFEST_METHOD_OUTGOING & acc)) {
            status = AJ_OK;
        }
        break;
    }
    AJ_InfoPrintf(("AJ_AccessControlCheck(msg=%p, name=%s, direction=%x): 0x%08X %X %s\n", msg, name, direction, msg->msgId, acc, AJ_StatusText(status)));

    return status;
}

AJ_Status AJ_AccessControlCheckProperty(const AJ_Message* msg, uint32_t id, const char* name, uint8_t direction)
{
    AJ_Status status;
    AccessControlMember* mbr;
    uint32_t peer;
    uint8_t acc;

    AJ_InfoPrintf(("AJ_AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x)\n", msg, id, name, direction));

    status = AJ_GetPeerIndex(name, &peer);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x): Peer not in table\n", msg, id, name, direction));
        return AJ_ERR_ACCESS;
    }

    mbr = FindAccessControlMember(id);
    if (NULL == mbr) {
        AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x): Property not in table AJ_ERR_ACCESS\n", msg, id, name, direction));
        return AJ_ERR_ACCESS;
    }

    status = AJ_ERR_ACCESS;
    acc = mbr->deny[peer] ? 0 : mbr->allow[peer];
    switch (direction) {
    case AJ_ACCESS_INCOMING:
        switch (msg->msgId & 0xFF) {
        case AJ_PROP_GET:
        case AJ_PROP_GET_ALL:
            if ((POLICY_PRPGET_INCOMING & acc) && (MANIFEST_PRPGET_INCOMING & acc)) {
                status = AJ_OK;
            } else {
                AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x, message id 0x%08X): acc = 0x%08X -> AJ_ERR_ACCESS\n", msg, id, name, direction, msg->msgId, (uint32_t)acc));
            }
            break;

        case AJ_PROP_SET:
            if ((POLICY_PRPSET_INCOMING & acc) && (MANIFEST_PRPSET_INCOMING & acc)) {
                status = AJ_OK;
            } else {
                AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x, message id 0x%08X): acc = 0x%08X -> AJ_ERR_ACCESS\n", msg, id, name, direction, msg->msgId, (uint32_t)acc));
            }
            break;

        default:
            AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x): Invalid message id 0x%08X\n", msg, id, name, direction, msg->msgId));
            AJ_ASSERT(0);
            break;
        }
        break;

    case AJ_ACCESS_OUTGOING:
        switch (msg->msgId & 0xFF) {
        case AJ_PROP_GET:
        case AJ_PROP_GET_ALL:
            if ((POLICY_PRPGET_OUTGOING & acc) && (MANIFEST_PRPGET_OUTGOING & acc)) {
                status = AJ_OK;
            } else {
                AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x, message id 0x%08X): acc = 0x%08X -> AJ_ERR_ACCESS\n", msg, id, name, direction, msg->msgId, (uint32_t)acc));
            }
            break;

        case AJ_PROP_SET:
            if ((POLICY_PRPSET_OUTGOING & acc) && (MANIFEST_PRPSET_OUTGOING & acc)) {
                status = AJ_OK;
            } else {
                AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x, message id 0x%08X): acc = 0x%08X -> AJ_ERR_ACCESS\n", msg, id, name, direction, msg->msgId, (uint32_t)acc));
            }
            break;

        default:
            AJ_WarnPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x): Invalid message id 0x%08X\n", msg, id, name, direction, msg->msgId));
            AJ_ASSERT(0);
            break;
        }
        break;
    }
    AJ_InfoPrintf(("AccessControlCheckProperty(msg=%p, id=0x%08X, name=%s, direction=%x): %s\n", msg, id, name, direction, AJ_StatusText(status)));

    return status;
}

/*
 * Clears all previous (if any) access control for an index
 */
AJ_Status AJ_AccessControlReset(const char* name)
{
    AJ_Status status;
    AccessControlMember* node = g_access;
    uint32_t peer;

    AJ_InfoPrintf(("AJ_AccessControlReset(name=%s)\n", name));

    status = AJ_GetPeerIndex(name, &peer);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_AccessControlReset(name=%s): Peer not in table\n", name));
        return status;
    }
    while (node) {
        node->allow[peer] = 0;
        node->deny[peer] = 0;
        node = node->next;
    }

    return AJ_OK;
}

void AJ_ManifestTemplateSet(AJ_PermissionRule* manifest)
{
    AJ_InfoPrintf(("AJ_ManifestTemplateSet(manifest=%p)\n", manifest));
    g_manifestRules = manifest;
}

#ifndef NDEBUG
static void PermissionMemberDump(AJ_PermissionMember* member)
{
    while (member) {
        AJ_InfoPrintf(("    Member %s (%x:%x)\n", member->mbr, member->type, member->action));
        member = member->next;
    }
}

static void PermissionRuleDump(AJ_PermissionRule* rule)
{
    while (rule) {
        AJ_InfoPrintf(("  Rule : %s : %s\n", rule->obj, rule->ifn));
        PermissionMemberDump(rule->members);
        rule = rule->next;
    }
}

static void ManifestDump(AJ_Manifest* manifest)
{
    if (manifest) {
        AJ_InfoPrintf(("Manifest\n"));
        AJ_InfoPrintf(("Version: %u\n", manifest->version));
        AJ_InfoPrintf(("Rules:\n----\n"));
        PermissionRuleDump(manifest->rules);
        AJ_InfoPrintf(("---\n"));
        AJ_InfoPrintf(("Thumbprint algorithm OID: %s\n", manifest->thumbprintAlgorithmOid));
        AJ_DumpBytes("Thumbprint", manifest->thumbprint, manifest->thumbprintSize);
        AJ_InfoPrintf(("Signature algorithm OID: %s\n", manifest->signatureAlgorithmOid));
        AJ_DumpBytes("Signature", manifest->signature, manifest->signatureSize);
    }
}

static void PermissionPeerDump(AJ_PermissionPeer* peer)
{
    while (peer) {
        AJ_InfoPrintf(("  Peer : Type %x\n", peer->type));
        switch (peer->type) {
        case AJ_PEER_TYPE_FROM_CA:
        case AJ_PEER_TYPE_WITH_PUBLIC_KEY:
            AJ_InfoPrintf(("    ECC PublicKey (algorithm %x, curve %x)\n", peer->pub.alg, peer->pub.crv));
            AJ_DumpBytes("X", peer->pub.x, KEY_ECC_SZ);
            AJ_DumpBytes("Y", peer->pub.y, KEY_ECC_SZ);
            break;

        case AJ_PEER_TYPE_WITH_MEMBERSHIP:
            AJ_InfoPrintf(("    ECC PublicKey (algorithm %x, curve %x)\n", peer->pub.alg, peer->pub.crv));
            AJ_DumpBytes("X", peer->pub.x, KEY_ECC_SZ);
            AJ_DumpBytes("Y", peer->pub.y, KEY_ECC_SZ);
            AJ_DumpBytes("GROUP", peer->group.data, peer->group.size);
            break;
        }
        peer = peer->next;
    }
}

static void PermissionACLDump(AJ_PermissionACL* acl)
{
    while (acl) {
        PermissionPeerDump(acl->peers);
        PermissionRuleDump(acl->rules);
        acl = acl->next;
    }
}

static void PolicyDump(AJ_Policy* policy)
{
    if (policy) {
        AJ_InfoPrintf(("Policy : Specification %x : Version %x\n", policy->specification, policy->version));
        PermissionACLDump(policy->acls);
    }
}
#endif

static void AJ_PermissionMemberFree(AJ_PermissionMember* head)
{
    AJ_PermissionMember* node;
    while (head) {
        node = head;
        head = head->next;
        AJ_Free(node);
    }
}

static void AJ_PermissionRuleFree(AJ_PermissionRule* head)
{
    AJ_PermissionRule* node;
    while (head) {
        node = head;
        head = head->next;
        AJ_PermissionMemberFree(node->members);
        AJ_Free(node);
    }
}

void AJ_ManifestFree(AJ_Manifest* manifest)
{
    if (manifest) {
        AJ_PermissionRuleFree(manifest->rules);
        AJ_Free(manifest);
    }
}

static void ManifestArrayElementFree(AJ_ManifestArray* node)
{
    if (NULL != node) {
        AJ_ManifestFree(node->manifest);
        AJ_Free(node);
    }
}

void AJ_ManifestArrayFree(AJ_ManifestArray* manifests)
{
    if (NULL != manifests) {
        AJ_ManifestArray* node;
        while (manifests) {
            node = manifests;
            manifests = manifests->next;
            ManifestArrayElementFree(node);
        }
    }
}

static void AJ_PermissionPeerFree(AJ_PermissionPeer* head)
{
    AJ_PermissionPeer* node;
    while (head) {
        node = head;
        head = head->next;
        AJ_Free(node);
    }
}

static void AJ_PermissionACLFree(AJ_PermissionACL* head)
{
    AJ_PermissionACL* node;
    while (head) {
        node = head;
        head = head->next;
        AJ_PermissionPeerFree(node->peers);
        AJ_PermissionRuleFree(node->rules);
        AJ_Free(node);
    }
}

void AJ_PolicyFree(AJ_Policy* policy)
{
    if (policy) {
        AJ_PermissionACLFree(policy->acls);
        AJ_Free(policy);
    }
}

//SIG = a(syy)
static AJ_Status AJ_PermissionMemberMarshal(const AJ_PermissionMember* head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (head) {
        status = AJ_MarshalArgs(msg, "(syy)", head->mbr, (uint8_t) head->type, (uint8_t) head->action);
        if (AJ_OK != status) {
            return status;
        }
        head = head->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

//SIG = a(ssa(syy))
static AJ_Status AJ_PermissionRuleMarshal(const AJ_PermissionRule* head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (head) {
        status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_MarshalArgs(msg, "ss", head->obj, head->ifn);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_PermissionMemberMarshal(head->members, msg);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_MarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            return status;
        }
        head = head->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

/* SIG = (ua(ssa(syy))saysay)       if useForDigest is FALSE
 * SIG = (ua(ssa(syy))says)         if useForDigest is TRUE
 */
AJ_Status AJ_ManifestMarshal(AJ_Manifest* manifest, AJ_Message* msg, uint8_t useForDigest)
{
    AJ_Status status;
    AJ_Arg outerStruct;

    if (NULL == manifest) {
        return AJ_ERR_INVALID;
    }

    status = AJ_MarshalContainer(msg, &outerStruct, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "u", manifest->version);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_PermissionRuleMarshal(manifest->rules, msg); // SIG = a(ssa(syy))
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "says",
                            manifest->thumbprintAlgorithmOid,
                            manifest->thumbprint,
                            manifest->thumbprintSize,
                            manifest->signatureAlgorithmOid);
    if (AJ_OK != status) {
        return status;
    }
    if (!useForDigest) {
        status = AJ_MarshalArgs(msg, "ay",
                                manifest->signature, manifest->signatureSize);

        if (AJ_OK != status) {
            return status;
        }
    }

    status = AJ_MarshalCloseContainer(msg, &outerStruct);

    return status;
}

//SIG = a(ua(ssa(syy))saysay)
AJ_Status AJ_ManifestArrayMarshal(AJ_ManifestArray* manifests, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;

    status = AJ_MarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (manifests) {
        status = AJ_ManifestMarshal(manifests->manifest, msg, FALSE); // SIG = (ua(ssa(syy))saysay)
        if (AJ_OK != status) {
            return status;
        }
        manifests = manifests->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

AJ_Status AJ_ManifestTemplateMarshal(AJ_Message* msg)
{
    return AJ_PermissionRuleMarshal(g_manifestRules, msg);
}

AJ_Status AJ_MarshalDefaultPolicy(AJ_CredField* field, AJ_PermissionPeer* peer_ca, AJ_PermissionPeer* peer_admin)
{
    AJ_Status status;
    /* Any authenticated peer */
    AJ_PermissionPeer peer_any;
    peer_any.type = AJ_PEER_TYPE_ANY_TRUSTED;
    peer_any.next = NULL;
    {
        /* All allowed */
        AJ_PermissionMember member_admin = { "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_PROVIDE | AJ_ACTION_OBSERVE | AJ_ACTION_MODIFY, NULL };
        /* Outgoing allowed, incoming signal allowed */
        AJ_PermissionMember member_any0 = { "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_PROVIDE, NULL };
        AJ_PermissionMember member_any1 = { "*", AJ_MEMBER_TYPE_SIGNAL, AJ_ACTION_OBSERVE, &member_any0 };

        AJ_PermissionRule rule_admin = { "*", "*", &member_admin, NULL };
        AJ_PermissionRule rule_any = { "*", "*", &member_any1, NULL };

        AJ_PermissionACL acl_ca = { peer_ca, NULL, NULL };
        AJ_PermissionACL acl_admin = { peer_admin, &rule_admin, &acl_ca };
        AJ_PermissionACL acl_any = { &peer_any, &rule_any, &acl_admin };

        AJ_Policy policy = { POLICY_SPECIFICATION_VERSION, 0, &acl_any };

        /* Marshal the policy */
        status = AJ_PolicyToBuffer(&policy, field);
    }
    return status;
}

//SIG = a(ya(yyayay)ay)
static AJ_Status AJ_PermissionPeerMarshal(const AJ_PermissionPeer* head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    AJ_Arg container3;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (head) {
        status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_MarshalArgs(msg, "y", head->type);
        if (AJ_OK != status) {
            return status;
        }

        // Marshal key (optional)
        status = AJ_MarshalContainer(msg, &container3, AJ_ARG_ARRAY);
        if (AJ_OK != status) {
            return status;
        }
        switch (head->type) {
        case AJ_PEER_TYPE_FROM_CA:
        case AJ_PEER_TYPE_WITH_PUBLIC_KEY:
        case AJ_PEER_TYPE_WITH_MEMBERSHIP:
            status = AJ_MarshalArgs(msg, "(yyayayay)", head->pub.alg, head->pub.crv, head->kid.data, head->kid.size, head->pub.x, KEY_ECC_SZ, head->pub.y, KEY_ECC_SZ);
            if (AJ_OK != status) {
                return status;
            }
            break;
        }
        status = AJ_MarshalCloseContainer(msg, &container3);
        if (AJ_OK != status) {
            return status;
        }

        // Marshal group (optional)
        if (AJ_PEER_TYPE_WITH_MEMBERSHIP == head->type) {
            status = AJ_MarshalArgs(msg, "ay", head->group.data, head->group.size);
        } else {
            status = AJ_MarshalArgs(msg, "ay", head->group.data, 0);
        }
        if (AJ_OK != status) {
            return status;
        }

        status = AJ_MarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            return status;
        }
        head = head->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = a(a(ya(yyayay)ay)a(ssa(syy)))
static AJ_Status AJ_PermissionACLMarshal(const AJ_PermissionACL* head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;

    status = AJ_MarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }
    while (head) {
        status = AJ_MarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_PermissionPeerMarshal(head->peers, msg);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_PermissionRuleMarshal(head->rules, msg);
        if (AJ_OK != status) {
            return status;
        }
        status = AJ_MarshalCloseContainer(msg, &container2);
        if (AJ_OK != status) {
            return status;
        }
        head = head->next;
    }
    status = AJ_MarshalCloseContainer(msg, &container1);

    return status;
}

//SIG = (qua(a(ya(yyayay)ay)a(ssa(syy))))
AJ_Status AJ_PolicyMarshal(const AJ_Policy* policy, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;

    if (NULL == policy) {
        return AJ_ERR_INVALID;
    }
    status = AJ_MarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalArgs(msg, "qu", policy->specification, policy->version);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_PermissionACLMarshal(policy->acls, msg);
    if (AJ_OK != status) {
        return status;
    }
    status = AJ_MarshalCloseContainer(msg, &container);

    return status;
}

//SIG = a(syy)
static AJ_Status AJ_PermissionMemberUnmarshal(AJ_PermissionMember** head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    AJ_PermissionMember* node;
    AJ_PermissionMember* curr = NULL;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        node = (AJ_PermissionMember*) AJ_Malloc(sizeof (AJ_PermissionMember));
        if (NULL == node) {
            goto Exit;
        }
        /* Push onto tail to maintain order */
        node->next = NULL;
        if (curr) {
            curr->next = node;
        } else {
            *head = node;
        }
        curr = node;
        status = AJ_UnmarshalArgs(msg, "syy", &node->mbr, &node->type, &node->action);
        if (AJ_OK != status) {
            goto Exit;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
    }
    if (AJ_ERR_NO_MORE != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto Exit;
    }

    return AJ_OK;

Exit:
    //Cleanup
    AJ_PermissionMemberFree(*head);
    *head = NULL;
    return AJ_ERR_INVALID;
}

//SIG = a(ssa(syy))
static AJ_Status AJ_PermissionRuleUnmarshal(AJ_PermissionRule** head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    AJ_PermissionRule* node;
    AJ_PermissionRule* curr = NULL;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        node = (AJ_PermissionRule*) AJ_Malloc(sizeof (AJ_PermissionRule));
        if (NULL == node) {
            goto Exit;
        }
        node->members = NULL;
        /* Push onto tail to maintain order */
        node->next = NULL;
        if (curr) {
            curr->next = node;
        } else {
            *head = node;
        }
        curr = node;
        status = AJ_UnmarshalArgs(msg, "ss", &node->obj, &node->ifn);
        if (AJ_OK != status) {
            goto Exit;
        }
        status = AJ_PermissionMemberUnmarshal(&node->members, msg);
        if (AJ_OK != status) {
            goto Exit;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
    }
    if (AJ_ERR_NO_MORE != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto Exit;
    }

    return AJ_OK;

Exit:
    //Cleanup
    AJ_PermissionRuleFree(*head);
    *head = NULL;
    return AJ_ERR_INVALID;
}

//SIG = a(ua(ssa(syy))saysay)
AJ_Status AJ_ManifestUnmarshal(AJ_Manifest** manifest, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Manifest* tmp;
    AJ_Arg outerStruct;
    uint8_t* beginning = NULL;

    tmp = (AJ_Manifest*) AJ_Malloc(sizeof (AJ_Manifest));
    if (NULL == tmp) {
        return AJ_ERR_RESOURCES;
    }

    memset(tmp, 0, sizeof(AJ_Manifest));

    beginning = msg->bus->sock.rx.readPtr;

    status = AJ_UnmarshalContainer(msg, &outerStruct, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_UnmarshalArgs(msg, "u", &tmp->version);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_PermissionRuleUnmarshal(&tmp->rules, msg); // SIG = a(ssa(syy))
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_UnmarshalArgs(msg, "saysay",
                              &tmp->thumbprintAlgorithmOid,
                              &tmp->thumbprint,
                              &tmp->thumbprintSize,
                              &tmp->signatureAlgorithmOid,
                              &tmp->signature,
                              &tmp->signatureSize);
    if (AJ_OK != status) {
        goto Exit;
    }

    status = AJ_UnmarshalCloseContainer(msg, &outerStruct);
    if (AJ_OK != status) {
        goto Exit;
    }

    AJ_ASSERT((msg->bus->sock.rx.readPtr - beginning) <= 0xFFFF);
    tmp->serializedSize = (uint16_t)(msg->bus->sock.rx.readPtr - beginning);

    *manifest = tmp;
    return AJ_OK;

Exit:

    AJ_ManifestFree(tmp);
    return status;
}


AJ_Status AJ_ManifestArrayUnmarshal(AJ_ManifestArray** manifests, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    AJ_Manifest* manifest;
    AJ_ManifestArray* node;
    AJ_ManifestArray* curr = NULL;

    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        return status;
    }

    while (AJ_OK == status) {
        status = AJ_ManifestUnmarshal(&manifest, msg);
        if (AJ_OK != status) {
            break;
        }

        node = (AJ_ManifestArray*)AJ_Malloc(sizeof(AJ_ManifestArray));
        if (NULL == node) {
            status = AJ_ERR_RESOURCES;
            break;
        }

        node->manifest = manifest;
        node->next = NULL;
        if (NULL != curr) {
            curr->next = node;
        } else {
            *manifests = node;
        }
        curr = node;
    }

    if (AJ_ERR_NO_MORE != status) {
        goto Exit;
    }

    status = AJ_UnmarshalCloseContainer(msg, &container);
    if (AJ_OK != status) {
        goto Exit;
    }

    return AJ_OK;

Exit:

    AJ_ManifestArrayFree(*manifests);
    *manifests = NULL;
    return status;

}

//SIG = a(ya(yyayayay)ay)
static AJ_Status AJ_PermissionPeerUnmarshal(AJ_PermissionPeer** head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    AJ_Arg container3;
    AJ_PermissionPeer* node;
    AJ_PermissionPeer* curr = NULL;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        node = (AJ_PermissionPeer*) AJ_Malloc(sizeof (AJ_PermissionPeer));
        if (NULL == node) {
            status = AJ_ERR_RESOURCES;
            goto Exit;
        }
        /* Push onto tail to maintain order */
        node->next = NULL;
        if (curr) {
            curr->next = node;
        } else {
            *head = node;
        }
        curr = node;
        status = AJ_UnmarshalArgs(msg, "y", &node->type);
        if (AJ_OK != status) {
            goto Exit;
        }

        status = AJ_UnmarshalContainer(msg, &container3, AJ_ARG_ARRAY);
        if (AJ_OK != status) {
            goto Exit;
        }
        // Unmarshal key (optional)
        switch (node->type) {
        case AJ_PEER_TYPE_FROM_CA:
        case AJ_PEER_TYPE_WITH_PUBLIC_KEY:
        case AJ_PEER_TYPE_WITH_MEMBERSHIP:
            status = AJ_UnmarshalECCPublicKey(msg, &node->pub, &node->kid);
            if (AJ_OK != status) {
                goto Exit;
            }
            break;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container3);
        if (AJ_OK != status) {
            goto Exit;
        }

        // Unmarshal group (optional)
        status = AJ_UnmarshalArgs(msg, "ay", &node->group.data, &node->group.size);
        if (AJ_OK != status) {
            goto Exit;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
    }
    if (AJ_ERR_NO_MORE != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto Exit;
    }

    return AJ_OK;

Exit:
    //Cleanup
    AJ_PermissionPeerFree(*head);
    *head = NULL;
    return AJ_ERR_INVALID;
}

//SIG = a(a(ya(yyayayay)ay)a(ssa(syy)))
static AJ_Status AJ_PermissionACLUnmarshal(AJ_PermissionACL** head, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container1;
    AJ_Arg container2;
    AJ_PermissionACL* node;
    AJ_PermissionACL* curr = NULL;

    status = AJ_UnmarshalContainer(msg, &container1, AJ_ARG_ARRAY);
    if (AJ_OK != status) {
        goto Exit;
    }
    while (AJ_OK == status) {
        status = AJ_UnmarshalContainer(msg, &container2, AJ_ARG_STRUCT);
        if (AJ_OK != status) {
            break;
        }
        node = (AJ_PermissionACL*) AJ_Malloc(sizeof (AJ_PermissionACL));
        if (NULL == node) {
            goto Exit;
        }
        node->peers = NULL;
        node->rules = NULL;
        /* Push onto tail to maintain order */
        node->next = NULL;
        if (curr) {
            curr->next = node;
        } else {
            *head = node;
        }
        curr = node;
        status = AJ_PermissionPeerUnmarshal(&node->peers, msg);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_PermissionRuleUnmarshal(&node->rules, msg);
        if (AJ_OK != status) {
            break;
        }
        status = AJ_UnmarshalCloseContainer(msg, &container2);
    }
    if (AJ_ERR_NO_MORE != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container1);
    if (AJ_OK != status) {
        goto Exit;
    }

    return AJ_OK;

Exit:
    //Cleanup
    AJ_PermissionACLFree(*head);
    *head = NULL;
    return AJ_ERR_INVALID;
}

//SIG = (qua(a(ya(yyayayay)ay)a(ssa(syy))))
AJ_Status AJ_PolicyUnmarshal(AJ_Policy** policy, AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg container;
    AJ_Policy* tmp = NULL;

    tmp = (AJ_Policy*) AJ_Malloc(sizeof (AJ_Policy));
    if (NULL == tmp) {
        goto Exit;
    }

    tmp->acls = NULL;
    status = AJ_UnmarshalContainer(msg, &container, AJ_ARG_STRUCT);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_UnmarshalArgs(msg, "qu", &tmp->specification, &tmp->version);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_PermissionACLUnmarshal(&tmp->acls, msg);
    if (AJ_OK != status) {
        goto Exit;
    }
    status = AJ_UnmarshalCloseContainer(msg, &container);
    if (AJ_OK != status) {
        goto Exit;
    }

    *policy = tmp;
    return AJ_OK;

Exit:
    //Cleanup
    AJ_PolicyFree(tmp);
    return AJ_ERR_INVALID;
}

AJ_Status AJ_ManifestDigest(AJ_CredField* manifest, uint8_t digest[AJ_SHA256_DIGEST_LENGTH])
{
    AJ_SHA256_Context* ctx;

    ctx = AJ_SHA256_Init();
    if (!ctx) {
        return AJ_ERR_RESOURCES;
    }
    AJ_SHA256_Update(ctx, manifest->data, manifest->size);
    return AJ_SHA256_Final(ctx, digest);
}

void AJ_PolicyUnload(void)
{
    AJ_CredFieldFree(&g_policy.buffer);
    g_policy.buffer.data = NULL;
    AJ_PolicyFree(g_policy.policy);
    g_policy.policy = NULL;
}

AJ_Status AJ_PolicyLoad(void)
{
    AJ_Status status;

    AJ_InfoPrintf(("PolicyLoad()\n"));

    /* Unload any previously loaded policy */
    AJ_PolicyUnload();

    /* Read the installed policy from NVRAM */
    status = AJ_CredentialGet(AJ_POLICY_INSTALLED | AJ_CRED_TYPE_POLICY, NULL, NULL, &g_policy.buffer);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("PolicyLoad(): No installed policy\n"));
        /* Read the default policy from NVRAM */
        status = AJ_CredentialGet(AJ_POLICY_DEFAULT | AJ_CRED_TYPE_POLICY, NULL, NULL, &g_policy.buffer);
    }
    if (AJ_OK != status) {
        AJ_InfoPrintf(("PolicyLoad(): No default policy\n"));
        goto Exit;
    }

    /* Unmarshal the policy */
    status = AJ_PolicyFromBuffer(&g_policy.policy, &g_policy.buffer);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("PolicyLoad(): Unmarshal failed\n"));
        goto Exit;
    }

#ifndef NDEBUG
    PolicyDump(g_policy.policy);
#endif

    return AJ_OK;

Exit:
    AJ_PolicyUnload();
    return AJ_ERR_INVALID;
}

AJ_Status AJ_AuthorisationRegister(const AJ_Object* list, uint8_t l)
{
    /* Register objects on the access control list, deregister any old entries first */
    AccessControlDeregister(l);
    return AccessControlRegister(list, l);
}

void AJ_AuthorisationClose(void)
{
    /* Unload access control list */
    AccessControlClose();
    /* Unload policy (if not unloaded during last handshake) */
    AJ_PolicyUnload();
}

uint8_t AJ_CommonPath(const char* name, const char* desc, uint8_t type)
{
    if (!name || !desc) {
        return 0;
    }
    /* Skip past common characters, or until a wildcard is hit */
    while (*name) {
        if ('*' == *name) {
            return 1;
        }
        if (*name++ != *desc++) {
            return 0;
        }
    }
    /*
     * Property annotation has read/write value directly after the name.
     * Methods and signals have a space before arguments or null if no arguments.
     */
    if (PROPERTY == type) {
        return ((WRITE_ONLY == *desc) || (READ_WRITE == *desc) || (READ_ONLY == *desc));
    } else {
        return (('\0' == *desc) || (' ' == *desc));
    }
}

static uint8_t MemberType(uint8_t a, uint8_t b)
{
    switch (a) {
    case AJ_MEMBER_TYPE_ANY:
        return 1;

    case AJ_MEMBER_TYPE_SIGNAL:
        return (SIGNAL == b);

    case AJ_MEMBER_TYPE_METHOD:
        return (METHOD == b);

    case AJ_MEMBER_TYPE_PROPERTY:
        return (PROPERTY == b);
    }
    return 0;
}

static uint8_t PermissionRuleAccess(AJ_PermissionRule* rule, AccessControlMember* acm, uint32_t peer, uint8_t with_public_key)
{
    AJ_PermissionMember* member;
    uint8_t type;
    const char* obj;
    const char* ifn;
    const char* mbr;
    uint8_t acc = 0;

    obj = acm->obj;
    ifn = acm->ifn;
    /* Skip over secure annotation */
    if ((SECURE_TRUE == *ifn) || (SECURE_OFF == *ifn)) {
        ifn++;
    }
    mbr = acm->mbr;
    type = MEMBER_TYPE(*mbr);
    mbr++;
    /* Skip over sessionless annotation */
    if (SESSIONLESS == *mbr) {
        mbr++;
    }

    while (rule) {
        if (AJ_CommonPath(rule->obj, obj, 0) && AJ_CommonPath(rule->ifn, ifn, 0)) {
            member = rule->members;
            while (member) {
                if (AJ_CommonPath(member->mbr, mbr, type) && MemberType(member->type, type)) {
                    /* Access is the union of all rules */
                    switch (type) {
                    case SIGNAL:
                        if (AJ_ACTION_OBSERVE & member->action) {
                            acc |= POLICY_SIGNAL_OUTGOING;
                        }
                        if (AJ_ACTION_PROVIDE & member->action) {
                            acc |= POLICY_SIGNAL_INCOMING;
                        }
                        break;

                    case METHOD:
                        if (AJ_ACTION_PROVIDE & member->action) {
                            acc |= POLICY_METHOD_OUTGOING;
                        }
                        if (AJ_ACTION_MODIFY & member->action) {
                            acc |= POLICY_METHOD_INCOMING;
                        }
                        break;

                    case PROPERTY:
                        if (AJ_ACTION_PROVIDE & member->action) {
                            acc |= POLICY_PRPSET_OUTGOING;
                            acc |= POLICY_PRPGET_OUTGOING;
                        }
                        if (AJ_ACTION_MODIFY & member->action) {
                            acc |= POLICY_PRPSET_INCOMING;
                        }
                        if (AJ_ACTION_OBSERVE & member->action) {
                            acc |= POLICY_PRPGET_INCOMING;
                        }
                        break;
                    }
                    /* Only apply DENY if WITH_PUBLIC_KEY and rule is all wildcard */
                    if (with_public_key && ('*' == rule->obj[0]) && ('*' == rule->ifn[0]) && ('*' == member->mbr[0]) && (0 == member->action)) {
                        /* Explicit deny both directions */
                        acm->deny[peer] = 1;
                    }
                }
                member = member->next;
            }
        }
        rule = rule->next;
    }

    return acc;
}

AJ_Status AJ_ManifestApply(AJ_Manifest* manifest, const char* name, AJ_AuthenticationContext* ctx)
{
    AJ_Status status;
    uint32_t peer;
    uint8_t acc;
    AccessControlMember* acm;
    AJ_CredField manifest_data;
    AJ_SHA256_Context* digestHashCtx;
    AJ_ECCSignature eccSignature;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];

    AJ_InfoPrintf(("AJ_ManifestApply(manifest=%p, name=%s, ctx=%p)\n", manifest, name, ctx));

    /* 2.16.840.1.101.3.4.2.1 is SHA-256. */
    if (0 != strcmp("2.16.840.1.101.3.4.2.1", manifest->thumbprintAlgorithmOid)) {
        /* No other algorithm is supported presently. */
        AJ_InfoPrintf(("Unsupported thumbprint algorithm: %s\n", manifest->thumbprintAlgorithmOid));
        return AJ_ERR_INVALID;
    }

    /* 1.2.840.10045.4.3.2 is ECDSA with SHA-256. */
    if (0 != strcmp("1.2.840.10045.4.3.2", manifest->signatureAlgorithmOid)) {
        AJ_InfoPrintf(("Unsupported signature algorithm: %s\n", manifest->signatureAlgorithmOid));
        return AJ_ERR_INVALID;
    }

    if (0 == ctx->kactx.ecdsa.thumbprintSize) {
        /* No stored thumbprint, so no way we can apply the manifest. */
        AJ_InfoPrintf(("No stored thumbprint to match manifest against\n"));
        return AJ_ERR_SECURITY_DIGEST_MISMATCH;
    }

    AJ_ASSERT(AJ_SHA256_DIGEST_LENGTH == ctx->kactx.ecdsa.thumbprintSize);

    if (manifest->thumbprintSize != ctx->kactx.ecdsa.thumbprintSize) {
        /* Thumbprint sizes differ. */
        AJ_InfoPrintf(("Thumbprint sizes differ: manifest is %u, stored is %u", (uint32_t)manifest->thumbprintSize, (uint32_t)ctx->kactx.ecdsa.thumbprintSize));
        return AJ_ERR_SECURITY_DIGEST_MISMATCH;
    }

    AJ_ASSERT(AJ_SHA256_DIGEST_LENGTH == ctx->kactx.ecdsa.thumbprintSize);
    if (0 != memcmp(manifest->thumbprint, ctx->kactx.ecdsa.thumbprint, ctx->kactx.ecdsa.thumbprintSize)) {
        AJ_InfoPrintf(("Manifest thumbprint does not equal thumbprint from authentication context\n"));
        AJ_DumpBytes("ManifestThumbprint", manifest->thumbprint, (uint32_t)manifest->thumbprintSize);
        AJ_DumpBytes("StoredThumbprint", ctx->kactx.ecdsa.thumbprint, (uint32_t)ctx->kactx.ecdsa.thumbprintSize);
        return AJ_ERR_SECURITY_DIGEST_MISMATCH;
    }

    if (manifest->signatureSize != (sizeof(eccSignature.r) + sizeof(eccSignature.s))) {
        AJ_InfoPrintf(("Signature field is wrong size: expected %u, got %u\n", (uint32_t)(sizeof(eccSignature.r) + sizeof(eccSignature.s)),
                       (uint32_t)manifest->signatureSize));
        return AJ_ERR_SECURITY_DIGEST_MISMATCH;
    }

    if (ctx->kactx.ecdsa.num < 2) {
        AJ_InfoPrintf(("Don't have identity certificate issuer's public key\n"));
        return AJ_ERR_SECURITY_DIGEST_MISMATCH;
    }

    manifest_data.size = manifest->serializedSize;
    manifest_data.data = (uint8_t*)AJ_Malloc(manifest->serializedSize);
    if (NULL == manifest_data.data) {
        return AJ_ERR_RESOURCES;
    }

    status = AJ_ManifestToBuffer(manifest, &manifest_data, TRUE);
    if (AJ_OK != status) {
        AJ_CredFieldFree(&manifest_data);
        return status;
    }

    if (manifest_data.size > manifest->serializedSize) {
        return AJ_ERR_END_OF_DATA;
    }

    /* Compute hash of manifest minus signature field. */
    digestHashCtx = AJ_SHA256_Init();
    if (!digestHashCtx) {
        AJ_CredFieldFree(&manifest_data);
        return AJ_ERR_RESOURCES;
    }

    AJ_SHA256_Update(digestHashCtx, manifest_data.data, manifest_data.size);
    status = AJ_SHA256_Final(digestHashCtx, digest);
    AJ_CredFieldFree(&manifest_data);
    if (AJ_OK != status) {
        return status;
    }

    /* Copy signature into signature object and verify. */
    eccSignature.alg = KEY_ALG_ECDSA_SHA256;
    eccSignature.crv = KEY_CRV_NISTP256;
    memcpy(eccSignature.r, manifest->signature, sizeof(eccSignature.r));
    memcpy(eccSignature.s, manifest->signature + sizeof(eccSignature.r), sizeof(eccSignature.s));

    status = AJ_ECDSAVerifyDigest(digest, &eccSignature, &ctx->kactx.ecdsa.key[1]);
    if (AJ_OK != status) {
        AJ_InfoPrintf(("Signature failed to verify\n"));
        return AJ_ERR_SECURITY_DIGEST_MISMATCH;
    }

    status = AJ_GetPeerIndex(name, &peer);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_ManifestApply(manifest=%p, name=%s): Peer not in table\n", manifest, name));
        return AJ_ERR_ACCESS;
    }

#ifndef NDEBUG
    ManifestDump(manifest);
#endif

    acm = g_access;
    while (acm) {
        acc = PermissionRuleAccess(manifest->rules, acm, peer, FALSE);
        /* Manifest permissions are stored in the most significant part of the byte */
        acc <<= 4;
#ifndef NDEBUG
        if (acc) {
            AJ_InfoPrintf(("Access: 0x%08X %s %s %s %x\n", acm->id, acm->obj, acm->ifn, acm->mbr, acc));
        }
#endif
        acm->allow[peer] |= acc;
        acm = acm->next;
    }

    return AJ_OK;
}

void AJ_ManifestArrayApply(AJ_ManifestArray* manifests, const char* name, AJ_AuthenticationContext* ctx)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_ManifestArrayApply(manifests=%p, name=%s, ctx=%p)\n", manifests, name, ctx));

    /* If the peer isn't enabled for Security 2.0, it won't have any manifests. This is OK. */
    if (NULL == manifests) {
        AJ_InfoPrintf(("AJ_ManifestArrayApply(name=%s, ctx=%p): Zero manifests received\n", name, ctx));
    }

    /* Try to apply any manifests we got. Log if they fail but carry on. */
    for (; NULL != manifests; manifests = manifests->next) {
        status = AJ_ManifestApply(manifests->manifest, name, ctx);
        if (AJ_OK != status) {
            AJ_InfoPrintf(("AJ_ManifestArrayApply(manifests=%p, name=%s, ctx=%p): AJ_ManifestApply of manifest %p returned %u\n",
                           manifests, name, ctx, manifests->manifest, status));
        }
    }
}

static uint8_t PermissionPeerFind(AJ_PermissionPeer* head, uint8_t type, AJ_ECCPublicKey* pub, DER_Element* group)
{
    while (head) {
        if (type == head->type) {
            if ((AJ_PEER_TYPE_ALL == type) || (AJ_PEER_TYPE_ANY_TRUSTED == type)) {
                return 1;
            } else {
                /* Type is FROM_CA or WITH_PUBLIC_KEY or WITH_MEMBERSHIP */
                AJ_ASSERT(pub);
                if (0 == memcmp((uint8_t*) pub, (uint8_t*) &head->pub, sizeof (AJ_ECCPublicKey))) {
                    if (AJ_PEER_TYPE_WITH_MEMBERSHIP == type) {
                        AJ_ASSERT(group);
                        if ((group->size == head->group.size) && (0 == memcmp(group->data, head->group.data, group->size))) {
                            return 1;
                        }
                    } else {
                        return 1;
                    }
                }
            }
        }
        head = head->next;
    }

    return 0;
}

AJ_Status AJ_PolicyApply(AJ_AuthenticationContext* ctx, const char* name)
{
    AJ_Status status;
    Policy* policy = &g_policy;
    uint32_t peer;
    uint8_t acc;
    AccessControlMember* acm;
    AJ_PermissionACL* acl;
    uint16_t state;
    uint16_t capabilities;
    uint16_t info;
    uint8_t found;
    size_t i;

    AJ_InfoPrintf(("AJ_PolicyApply(ctx=%p, name=%s)\n", ctx, name));

    status = AJ_GetPeerIndex(name, &peer);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_PolicyApply(ctx=%p, name=%s): Peer not in table\n", ctx, name));
        return AJ_ERR_ACCESS;
    }

    if (policy->policy) {
        acl = policy->policy->acls;
        while (acl) {
            found = 0;
            /* Look for a match in the peer list */
            found |= PermissionPeerFind(acl->peers, AJ_PEER_TYPE_ALL, NULL, NULL);
            if (AUTH_SUITE_ECDHE_NULL != ctx->suite) {
                found |= PermissionPeerFind(acl->peers, AJ_PEER_TYPE_ANY_TRUSTED, NULL, NULL);
            }
            if (AUTH_SUITE_ECDHE_ECDSA == ctx->suite) {
                AJ_ASSERT(ctx->kactx.ecdsa.key);
                /* With public key applies deny rules, flip the 2nd bit to indicate this type */
                /* Subject public key is in array index 0 */
                found |= (PermissionPeerFind(acl->peers, AJ_PEER_TYPE_WITH_PUBLIC_KEY, &ctx->kactx.ecdsa.key[0], NULL) << 1);
                /* Issuer public keys are in array index > 0, check root and all intermediates */
                for (i = 1; (i < ctx->kactx.ecdsa.num) && !found; i++) {
                    found |= PermissionPeerFind(acl->peers, AJ_PEER_TYPE_FROM_CA, &ctx->kactx.ecdsa.key[i], NULL);
                }
            }
            if (found) {
                acm = g_access;
                while (acm) {
                    acc = PermissionRuleAccess(acl->rules, acm, peer, found >> 1);
                    if (AUTH_SUITE_ECDHE_ECDSA != ctx->suite) {
                        /* We don't receive a manifest, so switch those bits on too */
                        acc |= (acc << 4);
                    }
#ifndef NDEBUG
                    if (acc) {
                        AJ_InfoPrintf(("Access: 0x%08X %s %s %s %x\n", acm->id, acm->obj, acm->ifn, acm->mbr, acc));
                    }
#endif
                    acm->allow[peer] |= acc;
                    acm = acm->next;
                }
            }
            acl = acl->next;
        }
    } else {
        AJ_InfoPrintf(("AJ_PolicyApply(ctx=%p, name=%p): No stored policy\n", ctx, name));
        /* Initial restricted access rights */
        acm = g_access;
        while (acm) {
            acm->allow[peer] = 0;
            switch (acm->id) {
            case AJ_METHOD_SECURITY_GET_PROP:
            case AJ_PROPERTY_SEC_VERSION:
            case AJ_PROPERTY_SEC_APPLICATION_STATE:
            case AJ_PROPERTY_SEC_MANIFEST_DIGEST:
            case AJ_PROPERTY_SEC_ECC_PUBLICKEY:
            case AJ_PROPERTY_SEC_MANUFACTURER_CERTIFICATE:
            case AJ_PROPERTY_SEC_MANIFEST_TEMPLATE:
            case AJ_PROPERTY_SEC_CLAIM_CAPABILITIES:
            case AJ_PROPERTY_SEC_CLAIM_CAPABILITIES_INFO:
            case AJ_PROPERTY_CLAIMABLE_VERSION:
                acm->allow[peer] = POLICY_INCOMING | MANIFEST_INCOMING;
                break;

            case AJ_METHOD_CLAIMABLE_CLAIM:
                /* Only allow claim if correct claim capabilities set */
                AJ_SecurityGetClaimConfig(&state, &capabilities, &info);
                if (APP_STATE_CLAIMABLE == state) {
                    if ((CLAIM_CAPABILITY_ECDHE_NULL & capabilities) && (AUTH_SUITE_ECDHE_NULL == ctx->suite)) {
                        acm->allow[peer] = POLICY_INCOMING | MANIFEST_INCOMING;
                    } else if ((CLAIM_CAPABILITY_ECDHE_PSK & capabilities) && (AUTH_SUITE_ECDHE_PSK == ctx->suite)) {
                        acm->allow[peer] = POLICY_INCOMING | MANIFEST_INCOMING;
                    } else if ((CLAIM_CAPABILITY_ECDHE_SPEKE & capabilities) && (AUTH_SUITE_ECDHE_SPEKE == ctx->suite)) {
                        acm->allow[peer] = POLICY_INCOMING | MANIFEST_INCOMING;
                    } else if ((CLAIM_CAPABILITY_ECDHE_ECDSA & capabilities) && (AUTH_SUITE_ECDHE_ECDSA == ctx->suite)) {
                        acm->allow[peer] = POLICY_INCOMING | MANIFEST_INCOMING;
                    }
                }
                break;

            case AJ_METHOD_SECURITY_SET_PROP:
            case AJ_PROPERTY_MANAGED_VERSION:
            case AJ_PROPERTY_MANAGED_IDENTITY:
            case AJ_PROPERTY_MANAGED_MANIFESTS:
            case AJ_PROPERTY_MANAGED_IDENTITY_CERT_ID:
            case AJ_PROPERTY_MANAGED_POLICY_VERSION:
            case AJ_PROPERTY_MANAGED_POLICY:
            case AJ_PROPERTY_MANAGED_DEFAULT_POLICY:
            case AJ_PROPERTY_MANAGED_MEMBERSHIP_SUMMARY:
            case AJ_METHOD_MANAGED_RESET:
            case AJ_METHOD_MANAGED_UPDATE_IDENTITY:
            case AJ_METHOD_MANAGED_UPDATE_POLICY:
            case AJ_METHOD_MANAGED_RESET_POLICY:
            case AJ_METHOD_MANAGED_INSTALL_MEMBERSHIP:
            case AJ_METHOD_MANAGED_REMOVE_MEMBERSHIP:
            case AJ_METHOD_MANAGED_START_MANAGEMENT:
            case AJ_METHOD_MANAGED_END_MANAGEMENT:
            case AJ_METHOD_MANAGED_INSTALL_MANIFESTS:
                /* Default not allowed */
                break;

            default:
                /* All allowed incoming and outgoing (Security 1.0) */
                acm->allow[peer] = POLICY_ACCESS | MANIFEST_ACCESS;
            }
            acm = acm->next;
        }
    }

    return AJ_OK;
}

AJ_Status AJ_MembershipApply(X509CertificateChain* root, AJ_ECCPublicKey* issuer, DER_Element* group, const char* name)
{
    AJ_Status status;
    Policy* policy = &g_policy;
    uint32_t peer;
    uint8_t acc;
    AccessControlMember* acm;
    AJ_PermissionACL* acl;
    uint8_t found;

    AJ_InfoPrintf(("AJ_MembershipApply(root=%p, issuer=%p, group=%p, name=%s)\n", root, issuer, group, name));

    status = AJ_GetPeerIndex(name, &peer);
    if (AJ_OK != status) {
        AJ_WarnPrintf(("AJ_MembershipApply(root=%p, issuer=%p, group=%p, name=%s): Peer not in table\n", root, issuer, group, name));
        return AJ_ERR_ACCESS;
    }

    if (policy->policy) {
        acl = policy->policy->acls;
        while (acl) {
            found = 0;
            /* Check if root issuer is in the peer list */
            if (issuer) {
                found = PermissionPeerFind(acl->peers, AJ_PEER_TYPE_WITH_MEMBERSHIP, issuer, group);
            }
            if (NULL != root) {
                /* Check if intermediate issuer is in the peer list */
                while (!found && (NULL != root->next)) {
                    found = PermissionPeerFind(acl->peers, AJ_PEER_TYPE_WITH_MEMBERSHIP, &root->certificate.tbs.publickey, group);
                    root = root->next;
                }
            }
            if (found) {
                acm = g_access;
                while (acm) {
                    acc = PermissionRuleAccess(acl->rules, acm, peer, FALSE);
#ifndef NDEBUG
                    if (acc) {
                        AJ_InfoPrintf(("Access: 0x%08X %s %s %s %x\n", acm->id, acm->obj, acm->ifn, acm->mbr, acc));
                    }
#endif
                    acm->allow[peer] |= acc;
                    acm = acm->next;
                }
            }
            acl = acl->next;
        }
    }

    return AJ_OK;
}

AJ_Status AJ_PolicyVersion(uint32_t* version)
{
    AJ_Status status;
    Policy* policy = &g_policy;

    status = AJ_PolicyLoad();
    if (AJ_OK != status) {
        AJ_InfoPrintf(("AJ_PolicyVersion(version=%p): Policy not loaded\n", version));
        return AJ_ERR_INVALID;
    }
    *version = policy->policy->version;
    AJ_PolicyUnload();

    return AJ_OK;
}

static uint32_t ValidIssuer(const X509Certificate* cert, uint32_t type)
{
    uint32_t eku = cert->tbs.extensions.type;
    /* This peer type can issue Identity and Unrestricted certificates */
    if ((AJ_PEER_TYPE_FROM_CA == type) && (AJ_CERTIFICATE_IDN_X509 & eku)) {
        return TRUE;
    }
    /* This peer type can issue Identity, Membership and Unrestricted certificates */
    if ((AJ_PEER_TYPE_WITH_MEMBERSHIP == type) && (AJ_CERTIFICATE_UNR_X509 & eku)) {
        return TRUE;
    }
    return FALSE;
}

AJ_Status AJ_PolicyFindAuthority(const X509CertificateChain* root)
{
    AJ_Status status;
    Policy* policy = &g_policy;
    AJ_PermissionACL* acl;
    AJ_PermissionPeer* peer;
    const X509CertificateChain* node;

    AJ_ASSERT(root);

    if (NULL == policy->policy) {
        AJ_InfoPrintf(("AJ_PolicyFindAuthority(root=%p): Policy not loaded\n", root));
        return AJ_ERR_INVALID;
    }

    status = AJ_ERR_SECURITY;
    acl = policy->policy->acls;
    while (acl) {
        peer = acl->peers;
        while (peer) {
            node = root;
            while ((node->next) && (node->certificate.tbs.extensions.ca)) {
                if (ValidIssuer(&node->next->certificate, peer->type)) {
                    if (0 == memcmp(&node->certificate.tbs.publickey, &peer->pub, sizeof (AJ_ECCPublicKey))) {
                        status = AJ_OK;
                        goto Exit;
                    }
                }
                node = node->next;
            }
            peer = peer->next;
        }
        acl = acl->next;
    }

Exit:
    return status;
}

AJ_Status AJ_PolicyVerifyCertificate(const X509Certificate* cert, AJ_ECCPublicKey* pub)
{
    AJ_Status status;
    Policy* policy = &g_policy;
    AJ_PermissionACL* acl;
    AJ_PermissionPeer* peer;

    AJ_ASSERT(cert);

    /*
     * Policy and/or certificate may not include AKI for CA,
     * we need to try all keys.
     */
    if (NULL == policy->policy) {
        AJ_InfoPrintf(("AJ_PolicyVerifyCertificate(cert=%p, pub=%p): Policy not loaded\n", cert, pub));
        return AJ_ERR_INVALID;
    }

    status = AJ_ERR_SECURITY;
    acl = policy->policy->acls;
    while (acl) {
        peer = acl->peers;
        while (peer) {
            if (ValidIssuer(cert, peer->type)) {
                /* Verify certificate */
                status = AJ_X509Verify(cert, &peer->pub);
                if (AJ_OK == status) {
                    memcpy(pub, &peer->pub, sizeof (AJ_ECCPublicKey));
                    goto Exit;
                }
            }
            peer = peer->next;
        }
        acl = acl->next;
    }

Exit:
    return status;
}

AJ_Status AJ_ManifestToBuffer(AJ_Manifest* manifest, AJ_CredField* field, uint8_t useForDigest)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    const char* messageSignature;
    if (useForDigest) {
        messageSignature = s_ManifestMsgArgDigestSignature;
    } else {
        messageSignature = s_ManifestMsgArgSignature;
    }
    AJ_LocalMsg(&bus, &hdr, &msg, messageSignature, field->data, field->size);
    status = AJ_ManifestMarshal(manifest, &msg, useForDigest);
    AJ_ASSERT((bus.sock.tx.writePtr - field->data) <= 0xFFFF);
    AJ_ASSERT((bus.sock.tx.writePtr - field->data) <= field->size);
    field->size = (uint16_t)(bus.sock.tx.writePtr - field->data);

    return status;
}

AJ_Status AJ_ManifestArrayToBuffer(AJ_ManifestArray* manifests, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    AJ_LocalMsg(&bus, &hdr, &msg, s_ManifestArrayMsgArgSignature, field->data, field->size);
    status = AJ_ManifestArrayMarshal(manifests, &msg);
    AJ_ASSERT((bus.sock.tx.writePtr - field->data) <= 0xFFFF);
    field->size = (uint16_t)(bus.sock.tx.writePtr - field->data);

    return status;
}

AJ_Status AJ_ManifestFromBuffer(AJ_Manifest** manifest, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    AJ_LocalMsg(&bus, &hdr, &msg, s_ManifestMsgArgSignature, field->data, field->size);
    status = AJ_ManifestUnmarshal(manifest, &msg);

    return status;
}

AJ_Status AJ_ManifestArrayFromBuffer(AJ_ManifestArray** manifests, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    AJ_LocalMsg(&bus, &hdr, &msg, s_ManifestArrayMsgArgSignature, field->data, field->size);
    status = AJ_ManifestArrayUnmarshal(manifests, &msg);

    return status;
}

AJ_Status AJ_PolicyToBuffer(AJ_Policy* policy, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    AJ_LocalMsg(&bus, &hdr, &msg, "(qua(a(ya(yyayayay)ay)a(ssa(syy))))", field->data, field->size);
    status = AJ_PolicyMarshal(policy, &msg);
    AJ_ASSERT((bus.sock.tx.writePtr - field->data) <= 0xFFFF);
    field->size = (uint16_t)(bus.sock.tx.writePtr - field->data);

    return status;
}

AJ_Status AJ_PolicyFromBuffer(AJ_Policy** policy, AJ_CredField* field)
{
    AJ_Status status;
    AJ_BusAttachment bus;
    AJ_MsgHeader hdr;
    AJ_Message msg;

    AJ_LocalMsg(&bus, &hdr, &msg, "(qua(a(ya(yyayayay)ay)a(ssa(syy))))", field->data, field->size);
    status = AJ_PolicyUnmarshal(policy, &msg);

    return status;
}

uint8_t AJ_ManifestHasSignature(const AJ_Manifest* manifest)
{
    AJ_InfoPrintf(("AJ_ManifestIsSigned(manifest=%p)\n", manifest));

    if ((NULL == manifest->thumbprintAlgorithmOid) || (0 == strlen(manifest->thumbprintAlgorithmOid))) {
        AJ_InfoPrintf(("Manifest has no thumbprint algorithm OID\n"));
        return FALSE;
    }

    if ((NULL == manifest->thumbprint) || (0 == manifest->thumbprintSize)) {
        AJ_InfoPrintf(("Manifest has no thumbprint\n"));
        return FALSE;
    }

    if ((NULL == manifest->signatureAlgorithmOid) || (0 == strlen(manifest->signatureAlgorithmOid))) {
        AJ_InfoPrintf(("Manifest has no signature algorithm OID\n"));
        return FALSE;
    }

    if ((NULL == manifest->signature) || (0 == manifest->signatureSize)) {
        AJ_InfoPrintf(("Manifest has no signature\n"));
        return FALSE;
    }

    return TRUE;
}

void AJ_ManifestArrayFilterUnsigned(AJ_ManifestArray** manifests)
{
    AJ_ManifestArray** elementAddress = manifests;
    AJ_ManifestArray* element;

    while (*elementAddress != NULL) {
        element = *elementAddress;

        if (AJ_ManifestHasSignature(element->manifest)) {
            elementAddress = &element->next;
        } else {
            *elementAddress = element->next;
            ManifestArrayElementFree(element);
        }
    }
}
