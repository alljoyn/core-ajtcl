/******************************************************************************
 * Copyright (c) 2013 - 2014, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE ABOUT

#include "alljoyn.h"
#include "aj_debug.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgABOUT = 0;
#endif

static const uint8_t aboutVersion = 1;
static const uint8_t aboutIconVersion = 1;

/*
 * Registered by the Property Store implementation
 */
static AJ_AboutPropGetter PropStoreGetter = NULL;

/*
 * About icon registration
 */
static struct {
    uint16_t size;
    const uint8_t* data;
    const char* mime;
    const char* URL;
} icon;

/*
 * Checked to see if announcements have been requested
 */
static uint8_t doAnnounce = TRUE;

void AJ_AboutRegisterPropStoreGetter(AJ_AboutPropGetter propGetter)
{
    PropStoreGetter = propGetter;
}

/*
 * Default about properties if there is no property store getter registered
 */
static AJ_Status MarshalDefaultProps(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg array;

    status = AJ_MarshalContainer(msg, &array, AJ_ARG_ARRAY);
    if (status == AJ_OK) {
        status = AJ_MarshalCloseContainer(msg, &array);
    }
    return status;
}

AJ_Status AJ_AboutInit(AJ_BusAttachment* bus, uint16_t boundPort)
{
    bus->aboutPort = boundPort;
    doAnnounce = TRUE;
    return AJ_AboutAnnounce(bus);
}

void AJ_AboutSetIcon(const uint8_t* data, uint16_t size, const char* mime, const char* url)
{
    icon.data = data;
    icon.size = data ? size : 0;
    icon.mime = mime;
    icon.URL = url;
}

/*
 * Handles a property GET request so marshals the property value to return
 */
static AJ_Status AboutGetProp(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    if (propId == AJ_PROPERTY_ABOUT_VERSION) {
        return AJ_MarshalArgs(replyMsg, "q", (uint16_t)aboutVersion);
    } else {
        return AJ_ERR_UNEXPECTED;
    }
}

AJ_Status AJ_AboutHandleGetProp(AJ_Message* msg)
{
    return AJ_BusPropGet(msg, AboutGetProp, NULL);
}

AJ_Status AJ_AboutHandleGetAboutData(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_OK;
    const char* language;

    status = AJ_UnmarshalArgs(msg, "s", &language);
    if (status == AJ_OK) {
        AJ_MarshalReplyMsg(msg, reply);
        if (PropStoreGetter) {
            status = PropStoreGetter(reply, language);
        } else {
            status = MarshalDefaultProps(reply);
        }
        if (status != AJ_OK) {
            status = AJ_MarshalErrorMsg(msg, reply, AJ_ErrLanguageNotSuppored);
        }
    }
    return status;
}

static AJ_Status MarshalObjectDescriptions(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg objList;
    AJ_ObjectIterator iter;
    const AJ_Object* obj;

    status = AJ_MarshalContainer(msg, &objList, AJ_ARG_ARRAY);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    /*
     * Announce object that a flagged for announcement and not hidden
     */
    for (obj = AJ_InitObjectIterator(&iter, AJ_OBJ_FLAG_ANNOUNCED | AJ_OBJ_FLAG_DESCRIBED, AJ_OBJ_FLAG_HIDDEN); obj != NULL; obj = AJ_NextObject(&iter)) {
        size_t i;
        AJ_Arg structure;
        AJ_Arg ifcList;
        const char* iface;

        status = AJ_MarshalContainer(msg, &structure, AJ_ARG_STRUCT);
        if (status != AJ_OK) {
            goto ErrorExit;
        }
        AJ_InfoPrintf(("Announcing object %s\n", obj->path));
        status = AJ_MarshalArgs(msg, "o", obj->path);
        if (status != AJ_OK) {
            goto ErrorExit;
        }
        status = AJ_MarshalContainer(msg, &ifcList, AJ_ARG_ARRAY);
        if (status != AJ_OK) {
            goto ErrorExit;
        }
        /*
         * Add the AllSeenIntrospectableInterface if this object is flagged as being described
         */
        if (obj->flags & AJ_OBJ_FLAG_DESCRIBED) {
            iface = AllSeenIntrospectableInterface;
            /*
             * Don't need the $ or # that indicate the interface is secure or not
             */
            if (*iface == '$' || *iface == '#') {
                ++iface;
            }
            AJ_InfoPrintf(("  %s\n", iface));
            status = AJ_MarshalArgs(msg, "s", iface);
            if (status != AJ_OK) {
                goto ErrorExit;
            }
        }
        for (i = 0; obj->interfaces[i]; ++i) {
            if (obj->interfaces[i] != AJ_PropertiesIface) {
                iface = obj->interfaces[i][0];
                if (iface) {
                    /*
                     * Don't need the $ or # that indicate the interface is secure or not
                     */
                    if (*iface == '$' || *iface == '#') {
                        ++iface;
                    }
                    AJ_InfoPrintf(("  %s\n", iface));
                    status = AJ_MarshalArgs(msg, "s", iface);
                    if (status != AJ_OK) {
                        goto ErrorExit;
                    }
                }
            }
        }
        status = AJ_MarshalCloseContainer(msg, &ifcList);
        if (status != AJ_OK) {
            goto ErrorExit;
        }
        status = AJ_MarshalCloseContainer(msg, &structure);
        if (status != AJ_OK) {
            goto ErrorExit;
        }
    }
    return AJ_MarshalCloseContainer(msg, &objList);

ErrorExit:
    return status;
}

AJ_Status AJ_AboutAnnounce(AJ_BusAttachment* bus)
{
    AJ_Status status = AJ_OK;
    AJ_Message announcement;

    if (!doAnnounce) {
        return status;
    }
    doAnnounce = FALSE;
    if (!bus->aboutPort) {
        AJ_InfoPrintf(("AJ_AboutAnnounce - nothing to announce\n"));
        return status;
    }

    AJ_InfoPrintf(("AJ_AboutAnnounce - announcing port=%d\n", bus->aboutPort));

    status = AJ_MarshalSignal(bus, &announcement, AJ_SIGNAL_ABOUT_ANNOUNCE, NULL, 0, ALLJOYN_FLAG_SESSIONLESS, 0);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    status = AJ_MarshalArgs(&announcement, "q", (uint16_t)aboutVersion);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    status = AJ_MarshalArgs(&announcement, "q", bus->aboutPort);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    status = MarshalObjectDescriptions(&announcement);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    if (PropStoreGetter) {
        status = PropStoreGetter(&announcement, "");
    } else {
        status = MarshalDefaultProps(&announcement);
    }
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    return AJ_DeliverMsg(&announcement);

ErrorExit:
    return status;
}

AJ_Status AJ_AboutHandleGetObjectDescription(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status = AJ_MarshalReplyMsg(msg, reply);
    if (status == AJ_OK) {
        return MarshalObjectDescriptions(reply);
    } else {
        return status;
    }
}

static AJ_Status AboutIconGetProp(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;

    if (propId == AJ_PROPERTY_ABOUT_ICON_VERSION_PROP) {
        status = AJ_MarshalArgs(replyMsg, "q", (uint16_t)aboutIconVersion);
    } else if (propId == AJ_PROPERTY_ABOUT_ICON_MIMETYPE_PROP) {
        status = AJ_MarshalArgs(replyMsg, "s", icon.mime ? icon.mime : "");
    } else if (propId == AJ_PROPERTY_ABOUT_ICON_SIZE_PROP) {
        status = AJ_MarshalArgs(replyMsg, "u", (uint32_t)icon.size);
    }
    return status;
}

AJ_Status AJ_AboutIconHandleGetProp(AJ_Message* msg)
{
    return AJ_BusPropGet(msg, AboutIconGetProp, NULL);
}

AJ_Status AJ_AboutIconHandleGetURL(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;

    status = AJ_MarshalReplyMsg(msg, reply);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    return AJ_MarshalArgs(reply, "s", icon.URL ? icon.URL : "");

ErrorExit:
    return status;
}

AJ_Status AJ_AboutIconHandleGetContent(AJ_Message* msg, AJ_Message* reply)
{
    AJ_Status status;
    uint32_t u = (uint32_t)icon.size;

    status = AJ_MarshalReplyMsg(msg, reply);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    status = AJ_DeliverMsgPartial(reply, u + 4);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    status = AJ_MarshalRaw(reply, &u, 4);
    if (status != AJ_OK) {
        goto ErrorExit;
    }
    return AJ_MarshalRaw(reply, icon.data, u);

ErrorExit:
    return status;
}

void AJ_AboutSetShouldAnnounce()
{
    doAnnounce = TRUE;
}

void AJ_AboutSetAnnounceObjects(AJ_Object* objList)
{
    if (objList) {
        while (objList->path) {
            objList->flags |= AJ_OBJ_FLAG_ANNOUNCED;
            ++objList;
        }
    }
}

