/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012,2013 AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE INTROSPECT

#include "aj_target.h"
#include "aj_debug.h"
#include "aj_introspect.h"
#include "aj_std.h"
#include "aj_msg.h"
#include "aj_msg_priv.h"
#include "aj_debug.h"
#include "aj_util.h"
#include "aj_debug.h"
#include "aj_config.h"
/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgINTROSPECT = 0;
#endif

/*
 * The various object lists
 */
const AJ_Object* objectLists[AJ_MAX_OBJECT_LISTS] = { AJ_StandardObjects, NULL, NULL };

/**
 * Struct for a reply context for a method call
 */
typedef struct _ReplyContext {
    AJ_Time callTime;    /**< Time the method call was made - used for timeouts */
    uint32_t timeout;    /**< How long to wait for a reply */
    uint32_t serial;     /**< Serial number for the reply message */
    uint32_t messageId;  /**< The unique message id for the call */
} ReplyContext;

static ReplyContext replyContexts[AJ_NUM_REPLY_CONTEXTS];

/**
 * Function used by XML generator to push generated XML
 */
typedef void (*XMLWriterFunc)(void* context, const char* str, uint32_t len);

#define IN_ARG     '<'  /* 0x3C */
#define OUT_ARG    '>'  /* 0x3E */

#define WRITE_ONLY '<'  /* 0x3C */
#define READ_WRITE '='  /* 0x3D */
#define READ_ONLY  '>'  /* 0x3E */

#define SEPARATOR  ' '

#define IS_DIRECTION(c) (((c) >= IN_ARG) && ((c) <= OUT_ARG))

#define MEMBER_TYPE(c) (((c) >> 4) - 2)

#define SIGNAL     MEMBER_TYPE('!')  /* ((0x21 >> 4) - 2) == 0 */
#define METHOD     MEMBER_TYPE('?')  /* ((0x3F >> 4) - 2) == 1 */
#define PROPERTY   MEMBER_TYPE('@')  /* ((0x40 >> 4) - 2) == 2 */

#define SECURE_TRUE  '$' /* Security is required for an interface that start with a '$' character */
#define SECURE_OFF   '#' /* Security is OFF, i.e. never required for an interface that starts with a '#' character */


static const char* const MemberOpen[] = {
    "  <signal",
    "  <method",
    "  <property"
};

static const char* const MemberClose[] = {
    "  </signal>\n",
    "  </method>\n",
    "/>\n"
};

static const char* const Access[] = {
    "\" access=\"write\"",
    "\" access=\"readwrite\"",
    "\" access=\"read\""
};

static const char* const Direction[] = {
    "\" direction=\"in\"/>\n",
    "\"/>\n",
    "\" direction=\"out\"/>\n"
};

static const char nameAttr[] = " name=\"";
static const char typeAttr[] = " type=\"";

static const char nodeOpen[] = "<node";
static const char nodeClose[] = "</node>\n";
static const char annotateSecure[] = "  <annotation name=\"org.alljoyn.Bus.Secure\" value=\"";
static const char secureTrue[] = "true\"/>\n";
static const char secureOff[] = "off\"/>\n";


static char ExpandAttribute(XMLWriterFunc XMLWriter, void* context, const char** str, const char* pre, const char* post)
{
    uint32_t len = 0;
    char next = 0;
    const char* s = *str;

    XMLWriter(context, pre, 0);
    while (*s) {
        char c = *s++;
        if (IS_DIRECTION(c) || (c == SEPARATOR)) {
            next = c;
            break;
        }
        ++len;
    }
    XMLWriter(context, *str, len);
    XMLWriter(context, post, 0);
    *str = s;

    return next;
}

static void XMLWriteTag(XMLWriterFunc XMLWriter, void* context, const char* tag, const char* attr, const char* val, uint32_t valLen, uint8_t atom)
{
    XMLWriter(context, tag, 0);
    XMLWriter(context, attr, 0);
    XMLWriter(context, val, valLen);
    XMLWriter(context, atom ? "\"/>\n" : "\">\n", 0);
}

static AJ_Status ExpandInterfaces(XMLWriterFunc XMLWriter, void* context, const AJ_InterfaceDescription* iface)
{
    if (!iface) {
        return AJ_OK;
    }
    while (*iface) {
        const char* const* entries = *iface;
        char flag = entries[0][0];
        uint8_t dBus_std_iface = FALSE;

        if ((flag == SECURE_TRUE) || (flag == SECURE_OFF)) {

            /* If it is a D-Bus interface, do not add any annotations.*/
            if ((strcmp(entries[0], "#org.freedesktop.DBus.Introspectable") == 0) ||
                (strcmp(entries[0], "#org.freedesktop.DBus.Properties") == 0) ||
                (strcmp(entries[0], "#org.freedesktop.DBus.Peer") == 0)) {
                dBus_std_iface = TRUE;
            }

            /*
             * if secure, skip the first char (the $) of the name
             */
            XMLWriteTag(XMLWriter, context, "<interface", nameAttr, entries[0] + 1, 0, FALSE);
            if (!dBus_std_iface) {
                XMLWriter(context, annotateSecure, 0);
                XMLWriter(context, (flag == SECURE_TRUE) ? secureTrue : secureOff, 0);
            }
        } else {
            XMLWriteTag(XMLWriter, context, "<interface", nameAttr, entries[0], 0, FALSE);
        }

        while (*(++entries)) {
            const char* member = *entries;
            uint8_t memberType = MEMBER_TYPE(*member++);
            uint8_t attr;
            if (memberType > 2) {
                AJ_ErrPrintf(("ExpandInterfaces(): AJ_ERR_UNEXPECTED"));
                return AJ_ERR_UNEXPECTED;
            }
            XMLWriter(context, MemberOpen[memberType], 0);
            attr = ExpandAttribute(XMLWriter, context, &member, nameAttr, "\"");
            if (memberType == PROPERTY) {
                uint8_t acc = attr - WRITE_ONLY;
                if (acc > 2) {
                    AJ_ErrPrintf(("ExpandInterfaces(): AJ_ERR_UNEXPECTED"));
                    return AJ_ERR_UNEXPECTED;
                }
                ExpandAttribute(XMLWriter, context, &member, typeAttr, Access[acc]);
            } else {
                XMLWriter(context, ">\n", 2);
                while (attr) {
                    uint8_t dir;
                    XMLWriter(context, "    <arg", 0);
                    if (IS_DIRECTION(*member)) {
                        dir = *member++ - IN_ARG;
                    } else {
                        dir = ExpandAttribute(XMLWriter, context, &member, nameAttr, "\"") - IN_ARG;
                    }
                    if ((dir != 0) && (dir != 2)) {
                        AJ_ErrPrintf(("ExpandInterfaces(): AJ_ERR_UNEXPECTED"));
                        return AJ_ERR_UNEXPECTED;
                    }
                    if (memberType == SIGNAL) {
                        dir = 1;
                    }
                    attr = ExpandAttribute(XMLWriter, context, &member, typeAttr, Direction[dir]);
                }
            }
            XMLWriter(context, MemberClose[memberType], 0);
        }
        XMLWriter(context, "</interface>\n", 0);
        ++iface;
    }
    return AJ_OK;
}

/*
 * Check if the path c is child of path p if so return pointer to the start of the child path
 * relative to the parent.
 */
static const char* ChildPath(const char* p, const char* c, uint32_t* sz)
{
    /*
     * Special case for parent == root (all nodes are children of root)
     */
    if ((p[0] == '/') && (p[1] == 0)) {
        ++p;
    }
    while (*p && (*p == *c)) {
        ++p;
        ++c;
    }
    if ((*p == '\0') && (*c == '/')) {
        uint32_t len = 0;
        ++c;
        while (c[len] && c[len] != '/') {
            ++len;
        }
        if (sz) {
            *sz = len;
        }
        /*
         * Return then isolated node name of the child
         */
        return len ? c : NULL;
    } else {
        return NULL;
    }
}

static const AJ_Object* FirstInstance(const char* path, const char* child, uint32_t sz, const AJ_Object* objList)
{
    while (objList->path) {
        uint32_t len;
        const char* c = ChildPath(path, objList->path, &len);
        if (c && (len == sz) && (memcmp(c, child, sz) == 0)) {
            return objList;
        }
        ++objList;
    }
    return NULL;
}

/*
 * Security applies if the interface is secure or if the object or it's parent object is flagged as
 * secure and the security is not explicitly OFF for the interface.
 */
static uint32_t SecurityApplies(const char* ifc, const AJ_Object* obj, const AJ_Object* objList)
{
    if (ifc) {
        if (*ifc == SECURE_TRUE) {
            return TRUE;
        }
        if (*ifc == SECURE_OFF) {
            return FALSE;
        }
    }
    if (obj->flags & AJ_OBJ_FLAG_SECURE) {
        return TRUE;
    }
    /*
     * Check that obj is not a child of a secure parent object
     */
    while (objList->path) {
        if ((objList->flags & AJ_OBJ_FLAG_SECURE) && ChildPath(objList->path, obj->path, NULL)) {
            return TRUE;
        }
        ++objList;
    }
    return FALSE;
}

static AJ_Status GenXML(XMLWriterFunc XMLWriter, void* context, const AJ_Object* obj, const AJ_Object* objList)
{
    AJ_Status status;
    const AJ_Object* list = objList;

    /*
     * Ignore objects that are hidden or disabled
     */
    if (obj->flags & (AJ_OBJ_FLAG_HIDDEN | AJ_OBJ_FLAG_DISABLED)) {
        return AJ_OK;
    }
    XMLWriteTag(XMLWriter, context, nodeOpen, nameAttr, obj->path, 0, FALSE);
    if (SecurityApplies(NULL, obj, objList)) {
        XMLWriter(context, annotateSecure, 0);
        XMLWriter(context, secureTrue, 0);
    }
    status = ExpandInterfaces(XMLWriter, context, obj->interfaces);
    if (status == AJ_OK) {
        /*
         * Check if the object has any child nodes
         */
        while (list->path) {
            uint32_t len;
            const char* child = ChildPath(obj->path, list->path, &len);
            /*
             * If there is a child check that this is the first instance of this child.
             */
            if (child && (FirstInstance(obj->path, child, len, objList) == list)) {
                XMLWriteTag(XMLWriter, context, nodeOpen, nameAttr, child, len, TRUE);
            }
            ++list;
        }
        XMLWriter(context, nodeClose, sizeof(nodeClose));
    }
    return status;
}

/*
 * Historically, Thin Client programs print the XML for their app objects as a
 * banner indicating they are alive.  For that reason we don't force users to
 * explicity turn on XML printing.  We just default it to on as long as we are
 * in a debug build.
 */
#ifndef NDEBUG

void PrintXML(void* context, const char* str, uint32_t len)
{
    if (len) {
        while (len--) {
            AJ_Printf("%c", *str++);
        }
    } else {
        AJ_Printf("%s", str);
    }
}

void AJ_PrintXML(const AJ_Object* obj)
{
    AJ_Status status;
    AJ_Object emptyList;

    while (obj->path) {
        emptyList.path = NULL;
        emptyList.interfaces = NULL;
        status = GenXML(PrintXML, NULL, obj, &emptyList);
        if (status != AJ_OK) {
            AJ_ErrPrintf(("\nFailed to generate XML - check interface descriptions of %s for errors\n", obj->path));
        }
        obj++;
    }
}
#endif

/*
 * Function to accumulate the length of the XML that will be generated
 */
void SizeXML(void* context, const char* str, uint32_t len)
{
    if (!len) {
        len = (uint32_t)strlen(str);
    }
    *((uint32_t*)context) += len;
}

typedef struct _WriteContext {
    AJ_Message* reply;
    uint32_t len;
    AJ_Status status;
} WriteContext;

void WriteXML(void* context, const char* str, uint32_t len)
{
    WriteContext* wctx = (WriteContext*)context;
    if (wctx->status == AJ_OK) {
        if (!len) {
            len = (uint32_t)strlen(str);
        }
        wctx->status = AJ_MarshalRaw(wctx->reply, str, len);
    }
}

AJ_Status AJ_HandleIntrospectRequest(const AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;
    const AJ_Object* obj = NULL;
    AJ_Object parent;
    WriteContext context;
    size_t list;

    for (list = AJ_APP_ID_FLAG; list < ArraySize(objectLists); ++list) {
        uint32_t children = 0;

        obj = objectLists[list];
        /*
         * Skip entry if there are no objects
         */
        if (!obj) {
            continue;
        }
        /*
         * For backwards compatibility the third entry is reserved for proxy objects. Going forward
         * proxy objects are identified in the object list by the AJ_OBJ_FLAG_IS_PROXY.
         */
        if (list == AJ_PRX_ID_FLAG) {
            continue;
        }
        /*
         * Find out which object we are introspecting. There are two possibilities:
         *
         * - The request has a complete object path to one of the application objects.
         * - The request has a path to a parent object of one or more application objects where the
         *   parent itself is just a place-holder in the object hierarchy.
         */
        for (; obj->path != NULL; ++obj) {
            /*
             * We don't introspect proxy objects
             */
            if (obj->flags & AJ_OBJ_FLAG_IS_PROXY) {
                continue;
            }
            if (strcmp(msg->objPath, obj->path) == 0) {
                break;
            }
            if (ChildPath(msg->objPath, obj->path, NULL)) {
                ++children;
            }
        }
        if (obj->path) {
            break;
        }
        /*
         * If there was not a direct match but the requested node has children we create
         * a temporary AJ_Object for the parent and introspect that object.
         */
        if (children) {
            parent.flags = 0;
            parent.path = msg->objPath;
            parent.interfaces = NULL;
            obj = &parent;
            break;
        }
    }
    /*
     * Skip objects that are hidden or disabled
     */
    if (obj && obj->path && !(obj->flags & (AJ_OBJ_FLAG_HIDDEN | AJ_OBJ_FLAG_DISABLED))) {
        /*
         * First pass computes the size of the XML string
         */
        context.len = 0;
        status = GenXML(SizeXML, &context.len, obj, objectLists[list]);
        if (status != AJ_OK) {
            AJ_ErrPrintf(("AJ_HandleIntrospectRequest(): Failed to generate XML. status=%s", AJ_StatusText(status)));
            return status;
        }
        /*
         * Second pass marshals the XML
         */
        AJ_InfoPrintf(("AJ_HandleIntrospectRequest() %d bytes of XML\n", context.len));
        AJ_MarshalReplyMsg(msg, reply);
        /*
         * Do a partial delivery
         */
        status = AJ_DeliverMsgPartial(reply, context.len + 5);
        /*
         * Marshal the string length
         */
        if (status == AJ_OK) {
            status = AJ_MarshalRaw(reply, &context.len, 4);
        }
        if (status == AJ_OK) {
            uint8_t nul = 0;
            context.status = AJ_OK;
            context.reply = reply;
            GenXML(WriteXML, &context, obj, objectLists[list]);
            status = context.status;
            if (status == AJ_OK) {
                /*
                 * Marshal the terminating NUL
                 */
                status = AJ_MarshalRaw(reply, &nul, 1);
            }
        }
    } else {
        /*
         * Return a ServiceUnknown error response
         */
        AJ_WarnPrintf(("AJ_HandleIntrospectRequest() NO MATCH for %s\n", msg->objPath));
        AJ_MarshalErrorMsg(msg, reply, AJ_ErrServiceUnknown);
    }
    return status;
}

/*
 * Check that the signature in the message matches the encoded signature in the string
 */
static AJ_Status CheckSignature(const char* encoding, const AJ_Message* msg)
{
    const char* sig = msg->signature ? msg->signature : "";
    char direction = (msg->hdr->msgType == AJ_MSG_METHOD_CALL) ? IN_ARG : OUT_ARG;

    /*
     * Wild card in the message is ok.
     */
    if (*sig == '*') {
        return AJ_OK;
    }
    while (*encoding) {
        /*
         * Skip until we find a direction character
         */
        while (*encoding && (*encoding++ != direction)) {
        }
        /*
         * Match a single arg to the signature
         */
        while (*encoding && (*sig == *encoding)) {
            ++sig;
            ++encoding;
        }
        if (*encoding && (*encoding != ' ')) {
            AJ_ErrPrintf(("CheckSignature(): AJ_ERR_SIGNATURE\n"));
            return AJ_ERR_SIGNATURE;
        }
    }
    /*
     * On a match we should have consumed both strings
     */
    return (*encoding == *sig) ? AJ_OK : AJ_ERR_SIGNATURE;
}

/*
 * Composes a signature from the member encoding from an interface description.
 */
static AJ_Status ComposeSignature(const char* encoding, char direction, char* sig, size_t len)
{
    while (*encoding) {
        /*
         * Skip until we find a direction character
         */
        while (*encoding && (*encoding++ != direction)) {
        }
        /*
         * Match a single arg to the signature
         */
        while (*encoding && (*encoding != ' ')) {
            if (--len == 0) {
                AJ_ErrPrintf(("ComposeSignature(): AJ_ERR_RESOURCES\n"));
                return AJ_ERR_RESOURCES;
            }
            *sig++ = *encoding++;
        }
    }
    *sig = '\0';
    return AJ_OK;
}

static AJ_Status MatchProp(const char* member, const char* prop, uint8_t op, const char** sig)
{
    const char* encoding = member;

    if (*encoding++ != '@') {
        AJ_ErrPrintf(("MatchProp(): AJ_ERR_NO_MATCH\n"));
        return AJ_ERR_NO_MATCH;
    }
    while (*prop) {
        if (*encoding++ != *prop++) {
            AJ_ErrPrintf(("MatchProp(): AJ_ERR_NO_MATCH\n"));
            return AJ_ERR_NO_MATCH;
        }
    }
    if ((op == AJ_PROP_GET) && (*encoding == WRITE_ONLY)) {
        AJ_ErrPrintf(("MatchProp(): AJ_ERR_DISALLOWED\n"));
        return AJ_ERR_DISALLOWED;
    }
    if ((op == AJ_PROP_SET) && (*encoding == READ_ONLY)) {
        AJ_ErrPrintf(("MatchProp(): AJ_ERR_DISALLOWED\n"));
        return AJ_ERR_DISALLOWED;
    }
    *sig = ++encoding;
    return AJ_OK;
}

static uint32_t MatchMember(const char* encoding, const AJ_Message* msg)
{
    const char* member = msg->member;
    char mtype = (msg->hdr->msgType == AJ_MSG_METHOD_CALL) ? '?' : '!';
    if (*encoding++ != mtype) {
        return FALSE;
    }
    while (*member) {
        if (*encoding++ != *member++) {
            return FALSE;
        }
    }
    return (*encoding == '\0') || (*encoding == ' ');
}

static AJ_InterfaceDescription FindInterface(const AJ_InterfaceDescription* interfaces, const char* iface, uint8_t* index)
{
    *index = 0;
    if (interfaces) {
        while (*interfaces) {
            AJ_InterfaceDescription desc = *interfaces++;
            const char* intfName = *desc;

            if (desc) {
                /*
                 * Skip security specifier when comparing the interface name
                 */
                if ((*intfName == SECURE_TRUE) || (*intfName == SECURE_OFF)) {
                    ++intfName;
                }
                if (strcmp(intfName, iface) == 0) {
                    return desc;
                }
            }
            *index += 1;
        }
    }
    return NULL;
}

/*
 * Match the object path. There are two wild card entries for object paths: '?'  matches any method
 * call and '!' matches any signal.  The method call wildcard is specifically to support the
 * introspection and ping methods. The signal wildcard allows for a single handler for a specific
 * signal emitted by any object. Note that these wildcards are expected to provide unique matches,
 * i.e. there should be no non-wildcarded entry in any object table that would also match.
 */
static uint8_t inline MatchPath(const char* path, AJ_Message* msg) {
    if ((*path == '?') && (msg->hdr->msgType == AJ_MSG_METHOD_CALL)) {
        return TRUE;
    }
    if ((*path == '!') && (msg->hdr->msgType == AJ_MSG_SIGNAL)) {
        return TRUE;
    }
    return strcmp(path, msg->objPath) == 0;
}

AJ_Status AJ_LookupMessageId(AJ_Message* msg, uint8_t* secure)
{
    uint8_t oIndex = 0;

    for (oIndex = 0; oIndex < ArraySize(objectLists); ++oIndex) {
        uint8_t pIndex = 0;
        const AJ_Object* obj = objectLists[oIndex];
        if (!obj) {
            continue;
        }
        for (; obj->path; ++pIndex, ++obj) {
            /*
             * Skip objects that are currently disabled
             */
            if (obj->flags & AJ_OBJ_FLAG_DISABLED) {
                continue;
            }
            if (MatchPath(obj->path, msg)) {
                uint8_t iIndex;
                AJ_InterfaceDescription desc = FindInterface(obj->interfaces, msg->iface, &iIndex);
                if (desc) {
                    uint8_t mIndex = 0;
                    *secure = SecurityApplies(*desc, obj, objectLists[oIndex]);
                    /*
                     * Skip the interface name and iterate over the members of the interface
                     */
                    while (*(++desc)) {
                        if (MatchMember(*desc, msg)) {
                            msg->msgId = (oIndex << 24) | (pIndex << 16) | (iIndex << 8) | mIndex;
                            AJ_InfoPrintf(("Identified message %x\n", msg->msgId));
                            return CheckSignature(*desc, msg);
                        }
                        ++mIndex;
                    }
                }
            }
        }
    }
    AJ_ErrPrintf(("LookupMessageId(): AJ_ERR_NO_MATCH\n"));
    return AJ_ERR_NO_MATCH;
}

#ifndef NDEBUG
/*
 * Validates an index into a NULL terminated array
 */
static uint8_t CheckIndex(const void* ptr, uint8_t index, size_t stride)
{
    if (!ptr) {
        return FALSE;
    }
    do {
        if (*((void**)ptr) == NULL) {
            AJ_ErrPrintf(("\n!!!Invalid msg identifier indicates programming error!!!\n"));
            return FALSE;
        }
        ptr = (((uint8_t*)ptr) + stride);
    } while (index--);
    return TRUE;
}
#endif

static AJ_Status UnpackMsgId(uint32_t msgId, const char** objPath, const char** iface, const char** member, uint8_t* secure)
{
    uint8_t oIndex = (msgId >> 24);
    uint8_t pIndex = (msgId >> 16);
    uint8_t iIndex = (msgId >> 8);
    uint8_t mIndex = (uint8_t)(msgId) + 1;
    const AJ_Object* obj;
    AJ_InterfaceDescription ifc;

#ifndef NDEBUG
    if ((oIndex > ArraySize(objectLists)) || !CheckIndex(objectLists[oIndex], pIndex, sizeof(AJ_Object))) {
        AJ_ErrPrintf(("UnpackMsgId(): AJ_ERR_INVALID\n"));
        return AJ_ERR_INVALID;
    }
    obj = &objectLists[oIndex][pIndex];
    if (!CheckIndex(obj->interfaces, iIndex, sizeof(AJ_InterfaceDescription))) {
        AJ_ErrPrintf(("UnpackMsgId(): AJ_ERR_INVALID\n"));
        return AJ_ERR_INVALID;
    }
    ifc = obj->interfaces[iIndex];
    if (!CheckIndex(ifc, mIndex, sizeof(AJ_InterfaceDescription))) {
        AJ_ErrPrintf(("UnpackMsgId(): AJ_ERR_INVALID\n"));
        return AJ_ERR_INVALID;
    }
#else
    obj = &objectLists[oIndex][pIndex];
    ifc = obj->interfaces[iIndex];
#endif
    if (obj->flags & AJ_OBJ_FLAG_DISABLED) {
        return AJ_ERR_INVALID;
    }
    if (objPath) {
        *objPath = obj->path;
    }
    *secure = SecurityApplies(*ifc, obj, objectLists[oIndex]);
    if (iface) {
        /*
         * Skip over security specifier if there is one
         */
        if ((ifc[0][0] == SECURE_TRUE) || (ifc[0][0] == SECURE_OFF)) {
            *iface = *ifc + 1;
        } else {
            *iface = *ifc;
        }
    }
    if (member) {
        *member = ifc[mIndex] + 1;
    }
    return AJ_OK;
}

AJ_Status AJ_MarshalPropertyArgs(AJ_Message* msg, uint32_t propId)
{
    AJ_Status status;
    const char* iface;
    const char* prop;
    uint8_t secure;
    size_t pos;
    AJ_Arg arg;

    status = UnpackMsgId(propId, NULL, &iface, &prop, &secure);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("AJ_MarhsalPropertyArgs(): status=%s\n", AJ_StatusText(status)));
        return status;
    }
    if (secure) {
        msg->hdr->flags |= AJ_FLAG_ENCRYPTED;
    }
    /*
     * Marshal interface name
     */
    AJ_MarshalArgs(msg, "s", iface);
    /*
     * Marshal property name
     */
    pos = AJ_StringFindFirstOf(prop, "<=>");
    AJ_InitArg(&arg, AJ_ARG_STRING, 0, prop, pos);
    status = AJ_MarshalArg(msg, &arg);
    /*
     * If setting a property handle the variant setup
     */
    if ((status == AJ_OK) && ((msg->msgId & 0xFF) == AJ_PROP_SET)) {
        char sig[16];
        ComposeSignature(prop, prop[pos], sig, sizeof(sig));
        status = AJ_MarshalVariant(msg, sig);
    }
    return status;
}

/*
 * Hook for unit tests
 */
#ifndef NDEBUG
AJ_MutterHook MutterHook = NULL;
#endif

AJ_Status AJ_InitMessageFromMsgId(AJ_Message* msg, uint32_t msgId, uint8_t msgType, uint8_t* secure)
{
    /*
     * Static buffer for holding the signature for the message currently being marshaled. Since this
     * implementation can only marshal one message at a time we only need one of these buffers. The
     * size of the buffer dictates the maximum size signature we can marshal. The wire protocol
     * allows up to 255 characters in a signature but that would represent an outgrageously complex
     * message argument list.
     */
    static char msgSignature[32];
    AJ_Status status = AJ_OK;

#ifndef NDEBUG
    if (MutterHook) {
        return MutterHook(msg, msgId, msgType);
    }
#endif
    if (msgType == AJ_MSG_ERROR) {
        /*
         * The only thing to initialize for errors is the msgId
         */
        msg->msgId = AJ_REPLY_ID(msgId);
        /*
         * Get the secure flag if we have a valid message id this will ensure that the error
         * response is encrypted if that is what is expected.
         */
        if (msg->msgId != AJ_INVALID_MSG_ID) {
            status = UnpackMsgId(msgId, NULL, NULL, NULL, secure);
        }
    } else {
        const char* member = NULL;
        char direction = (msgType == AJ_MSG_METHOD_CALL) ? IN_ARG : OUT_ARG;
        /*
         * The rest is just indexing into the object and interface descriptions.
         */
        if (msgType == AJ_MSG_METHOD_RET) {
            msg->msgId = AJ_REPLY_ID(msgId);
            status = UnpackMsgId(msgId, NULL, NULL, &member, secure);
        } else {
            msg->msgId = msgId;
            status = UnpackMsgId(msgId, &msg->objPath, &msg->iface, &member, secure);
            if (status == AJ_OK) {
                /*
                 * Validate the object path
                 */
                if (!msg->objPath) {
                    status = AJ_ERR_OBJECT_PATH;
                } else if (*msg->objPath == '*') {
                    /*
                     * The wildcard object path is a special for case methods implemented by all
                     * objects. In the message header need a valid object path, it doesn't matter
                     * which one by definition so use the root object because it is always valid.
                     */
                    msg->objPath = "/";
                } else if (*msg->objPath != '/') {
                    status = AJ_ERR_OBJECT_PATH;
                }
                msg->member = member;
            }
        }
        /*
         * Compose the signature from information in the member encoding.
         */
        if (status == AJ_OK) {
            status = ComposeSignature(member, direction, msgSignature, sizeof(msgSignature));
            if (status == AJ_OK) {
                msg->signature = msgSignature;
            }
        }
    }

    return status;
}

static AJ_Status CheckReturnSignature(AJ_Message* msg, uint32_t msgId)
{
    AJ_Status status;
    uint8_t secure = FALSE;
    const char* member;

    status = UnpackMsgId(msgId, NULL, NULL, &member, &secure);
    if (status != AJ_OK) {
        AJ_ErrPrintf(("CheckReturnSignature(): status=%s\n", AJ_StatusText(status)));
        return status;
    }
    /*
     * Check that if the interface was flagged secure that the reply was encrypted
     */
    if (secure && !(msg->hdr->flags & AJ_FLAG_ENCRYPTED)) {
        return AJ_ERR_SECURITY;
    }
    /*
     * Nothing to check for error messages
     */
    if (msg->hdr->msgType != AJ_MSG_ERROR) {
        status = CheckSignature(member, msg);
    }
    if (status == AJ_OK) {
        msg->msgId = AJ_REPLY_ID(msgId);
    }
    return status;
}

static ReplyContext* FindReplyContext(uint32_t serial) {
    size_t i;
    for (i = 0; i < ArraySize(replyContexts); ++i) {
        if (replyContexts[i].serial == serial) {
            return &replyContexts[i];
        }
    }
    return NULL;
}

AJ_Status AJ_IdentifyProperty(AJ_Message* msg, const char* iface, const char* prop, uint32_t* propId, const char** sigPtr, uint8_t* secure)
{
    AJ_Status status = AJ_ERR_NO_MATCH;
    uint8_t oIndex = (msg->msgId >> 24);
    uint8_t pIndex = (msg->msgId >> 16);
    uint8_t iIndex;
    const AJ_Object* obj;
    AJ_InterfaceDescription desc;

#ifndef NDEBUG
    if ((oIndex > ArraySize(objectLists)) || !CheckIndex(objectLists[oIndex], pIndex, sizeof(AJ_Object))) {
        AJ_ErrPrintf(("AJ_IdentifyProperty(): AJ_ERR_INVALID\n"));
        return AJ_ERR_INVALID;
    }
#endif
    obj = &objectLists[oIndex][pIndex];

    *propId = AJ_INVALID_PROP_ID;

    desc = FindInterface(obj->interfaces, iface, &iIndex);
    if (desc) {
        uint8_t mIndex = 0;
        /*
         * Security is based on the interface the property is defined on.
         */
        *secure = SecurityApplies(*desc, obj, objectLists[oIndex]);
        /*
         * Iterate over the interface members to locate the property is being accessed.
         */
        while (*(++desc)) {
            status = MatchProp(*desc, prop, msg->msgId & 0xFF, sigPtr);
            if (status != AJ_ERR_NO_MATCH) {
                if (status == AJ_OK) {
                    *propId = (oIndex << 24) | (pIndex << 16) | (iIndex << 8) | mIndex;
                    AJ_InfoPrintf(("Identified property %s:%s id=%x sig=\"%s\"\n", iface, prop, *propId, *sigPtr));
                }
                break;
            }
            ++mIndex;
        }
    }
    return status;
}

AJ_Status AJ_UnmarshalPropertyArgs(AJ_Message* msg, uint32_t* propId, const char** sig)
{
    AJ_Status status;
    uint8_t secure = FALSE;
    char* iface;
    char* prop;

    status = AJ_UnmarshalArgs(msg, "ss", &iface, &prop);
    if (status == AJ_OK) {
        status = AJ_IdentifyProperty(msg, iface, prop, propId, sig, &secure);
        /*
         * If the interface is secure check the message must be encrypted
         */
        if ((status == AJ_OK) && secure && !(msg->hdr->flags & AJ_FLAG_ENCRYPTED)) {
            status = AJ_ERR_SECURITY;
            AJ_WarnPrintf(("Security violation accessing property\n"));
        }
    }
    return status;
}

AJ_Status AJ_IdentifyMessage(AJ_Message* msg)
{
    AJ_Status status = AJ_ERR_NO_MATCH;
    uint8_t secure = FALSE;
#ifndef NDEBUG
    if (MutterHook) {
        return AJ_OK;
    }
#endif
    msg->msgId = AJ_INVALID_MSG_ID;
    if ((msg->hdr->msgType == AJ_MSG_METHOD_CALL) || (msg->hdr->msgType == AJ_MSG_SIGNAL)) {
        /*
         * Methods and signals
         */
        status = AJ_LookupMessageId(msg, &secure);
        if ((status == AJ_OK) && secure && !(msg->hdr->flags & AJ_FLAG_ENCRYPTED)) {
            AJ_ErrPrintf(("AJ_IdentifyMessage(): AJ_ERR_SECURITY\n"));
            status = AJ_ERR_SECURITY;
        }
        /*
         * Generate an error response for an invalid method call rather than reporting an invalid
         * message id to the application.
         */
        if ((status != AJ_OK) && (msg->hdr->msgType == AJ_MSG_METHOD_CALL) && !(msg->hdr->flags & AJ_FLAG_NO_REPLY_EXPECTED)) {
            AJ_Message reply;

            AJ_DumpMsg("Rejecting unidentified method call", msg, FALSE);
            AJ_MarshalStatusMsg(msg, &reply, status);
            status = AJ_DeliverMsg(&reply);
            /*
             * Cleanup the message we are ignoring.
             */
            AJ_CloseMsg(msg);
        }
    } else {
        ReplyContext* repCtx = FindReplyContext(msg->replySerial);
        if (repCtx) {
            status = CheckReturnSignature(msg, repCtx->messageId);
            /*
             * Release the reply context
             */
            repCtx->serial = 0;
        }
    }
    return status;
}

void AJ_RegisterObjects(const AJ_Object* localObjects, const AJ_Object* proxyObjects)
{
    AJ_ASSERT(AJ_PRX_ID_FLAG < ArraySize(objectLists));
    objectLists[AJ_APP_ID_FLAG] = localObjects;
    objectLists[AJ_PRX_ID_FLAG] = proxyObjects;
}

AJ_Status AJ_RegisterObjectList(const AJ_Object* objList, uint8_t index)
{
    if (index <= AJ_PRX_ID_FLAG) {
        return AJ_ERR_DISALLOWED;
    }
    if (index >= ArraySize(objectLists)) {
        return AJ_ERR_RANGE;
    }
    objectLists[index] = objList;
    return AJ_OK;
}

AJ_Status AJ_SetProxyObjectPath(AJ_Object* proxyObjects, uint32_t msgId, const char* objPath)
{
    int i;
    uint8_t oIndex = (msgId >> 24);
    uint8_t pIndex = (msgId >> 16);

    if ((oIndex != AJ_PRX_ID_FLAG) || (proxyObjects != objectLists[oIndex])) {
        AJ_ErrPrintf(("AJ_SetProxyObjectPath(): AJ_ERR_UNKNOWN\n"));
        return AJ_ERR_UNKNOWN;
    }
    for (i = 0; i < pIndex; ++i) {
        if (!proxyObjects[i].interfaces) {
            AJ_ErrPrintf(("AJ_SetProxyObjectPath(): AJ_ERR_UNKNOWN\n"));
            return AJ_ERR_UNKNOWN;
        }
    }
    proxyObjects[pIndex].path = objPath;
    return AJ_OK;
}

AJ_Status AJ_AllocReplyContext(AJ_Message* msg, uint32_t timeout)
{
    if (msg->hdr->flags & AJ_FLAG_NO_REPLY_EXPECTED) {
        /*
         * Not expecting a reply so don't allocate a reply context
         */
        return AJ_OK;
    } else {
        ReplyContext* repCtx = FindReplyContext(0);

        AJ_ASSERT(msg->hdr->msgType == AJ_MSG_METHOD_CALL);

        if (repCtx) {
            repCtx->serial = msg->hdr->serialNum;
            repCtx->messageId = msg->msgId;
            repCtx->timeout = timeout ? timeout : AJ_DEFAULT_REPLY_TIMEOUT;
            AJ_InitTimer(&repCtx->callTime);
            return AJ_OK;
        } else {
            AJ_ErrPrintf(("AJ_AllocReplyContext(): Failed to allocate reply context.  status=AJ_ERR_RESOURCES\n"));
            return AJ_ERR_RESOURCES;
        }
    }
}

void AJ_ReleaseReplyContext(AJ_Message* msg)
{
    if (msg->hdr->msgType == AJ_MSG_METHOD_CALL) {
        ReplyContext* repCtx = FindReplyContext(msg->hdr->serialNum);
        if (repCtx) {
            repCtx->serial = 0;
        }
    }
}

uint8_t AJ_TimedOutMethodCall(AJ_Message* msg)
{
    ReplyContext* repCtx = replyContexts;
    size_t i;
    for (i = 0; i < ArraySize(replyContexts); ++i, ++repCtx) {
        if (repCtx->serial && (AJ_GetElapsedTime(&repCtx->callTime, TRUE) > repCtx->timeout)) {
            /*
             * Set the reply serial and message id for the timeout error
             */
            msg->replySerial = repCtx->serial;
            msg->msgId = AJ_REPLY_ID(repCtx->messageId);
            /*
             * Release the reply context
             */
            repCtx->serial = 0;
            return TRUE;
        }
    }
    return FALSE;
}

void AJ_ReleaseReplyContexts(void)
{
    memset(replyContexts, 0, sizeof(replyContexts));
}

AJ_Status AJ_SetObjectFlags(const char* objPath, uint8_t setFlags, uint8_t clearFlags)
{
    AJ_Status status = AJ_ERR_NO_MATCH;
    AJ_Object* list = (AJ_Object*)objectLists[AJ_APP_ID_FLAG];

    if (list && objPath) {
        /*
         * Set flags on the object and all its children
         */
        while (list->path) {
            if ((strcmp(objPath, list->path) == 0) || ChildPath(objPath, list->path, NULL)) {
                list->flags &= ~clearFlags;
                list->flags |= setFlags;
                AJ_InfoPrintf(("Setting flags for %s to 0x%02x\n", list->path, list->flags));
                status = AJ_OK;
            }
            ++list;
        }
    }
    return status;
}

AJ_MemberType AJ_GetMemberType(uint32_t identifier, const char** member, uint8_t* isSecure)
{
    const char* name;
    uint8_t secure;
    AJ_Status status = UnpackMsgId(identifier, NULL, NULL, &name, &secure);
    if (status == AJ_OK) {
        if (isSecure) {
            *isSecure = secure;
        }
        if (member) {
            *member = name;
        }
        return (AJ_MemberType) * (name - 1);
    } else {
        return AJ_INVALID_MEMBER;
    }
}

const AJ_Object* AJ_InitObjectIterator(AJ_ObjectIterator* iter, uint8_t inFlags, uint8_t exFlags)
{
    iter->fin = inFlags;
    iter->fex = exFlags;
    iter->l = 0;
    iter->n = 0;
    return AJ_NextObject(iter);
}

const AJ_Object* AJ_NextObject(AJ_ObjectIterator* iter)
{
    while (iter->l < ArraySize(objectLists)) {
        const AJ_Object* list = objectLists[iter->l];
        if (list) {
            while (list[iter->n].path) {
                const AJ_Object* obj = &list[iter->n++];
                if ((obj->flags & iter->fin) && !(obj->flags & iter->fex)) {
                    return obj;
                }
            }
        }
        iter->n = 0;
        ++iter->l;
    }
    return NULL;
}
