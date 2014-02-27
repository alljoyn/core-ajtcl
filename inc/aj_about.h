#ifndef _AJ_ABOUT_H
#define _AJ_ABOUT_H
/**
 * @file aj_about.h
 * @defgroup aj_about Bus Attachment
 * @{
 */
/******************************************************************************
 * Copyright (c) 2013-2014, AllSeen Alliance. All rights reserved.
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

#include "aj_target.h"
#include "aj_status.h"
#include "aj_util.h"

/**
 * Prototype for a function provided by the property store for getting ANNOUNCE and ABOUT properties
 *
 * @param reply     The message to marshal the property values into. The getter can also figure out
 *                  from the msgId in the reply message if the reply is for ANNOUNCE or ABOUT.
 *
 * @param language  The language to use to return the string properties. If this is NULL the default
 *                  language will be used.
 *
 * @return   Return AJ_OK if the properties were succesfully marshaled into the reply.
 *
 */
typedef AJ_Status (*AJ_AboutPropGetter)(AJ_Message* reply, const char* language);

/**
 * Called by the property store to register the about property getter. Functionality will be limited
 * if there is not property store.
 *
 * @param propGetter  The property getter function being registered.
 */
void AJ_AboutRegisterPropStoreGetter(AJ_AboutPropGetter propGetter);

/**
 * Initialize About and send the initial announcement.
 *
 * @param bus        The bus attachment
 * @param boundPort  Session port the application has bound
 */
AJ_Status AJ_AboutInit(AJ_BusAttachment* bus, uint16_t boundPort);

/**
 * Emit an announcement if one has been scheduled.
 *
 * @param bus   The bus attachment context.
 */
AJ_Status AJ_AboutAnnounce(AJ_BusAttachment* bus);

/**
 * Set a device icon to be returned by About
 *
 * @param icon  Pointer to the icon data blob. This pointer must remain live until the next time this
 *              function is called. Can be NULL if there is not icon data.
 * @param size  The size of the icon data blob.
 * @param mime  The mime type for the icon
 * @param url   Optional URL for an icon
 */
void AJ_AboutSetIcon(const uint8_t* icon, uint16_t size, const char* mimeType, const char* url);

/**
 * Handle a GET_PROP method call
 *
 * @param msg    The GET_PROP message
 *
 * @return  Return AJ_Status
 *          - AJ_OK if successfully handled
 *          - AJ_ERR_WRITE if there was a write failure
 */
AJ_Status AJ_AboutHandleGetProp(AJ_Message* msg);

/**
 * Handle a GET_ABOUT_DATA method call
 *
 * @param msg    The GET_ABOUT_DATA message
 * @param reply  The GET_ABOUT_DATA reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK if successfully handled
 *          - AJ_ERR_WRITE if there was a write failure
 */
AJ_Status AJ_AboutHandleGetAboutData(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a GET_ABOUT_OBJECT_DESCRIPTION method call
 *
 * @param msg    The GET_ABOUT_OBJECT_DESCRIPTION message
 * @param reply  The GET_ABOUT_OBJECT_DESCRIPTION reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK if successfully handled
 *          - AJ_ERR_WRITE if there was a write failure
 */
AJ_Status AJ_AboutHandleGetObjectDescription(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a GET_PROP method call
 *
 * @param msg    The GET_PROP message
 *
 * @return  Return AJ_Status
 *          - AJ_OK if successfully handled
 *          - AJ_ERR_WRITE if there was a write failure
 */
AJ_Status AJ_AboutIconHandleGetProp(AJ_Message* msg);

/**
 * Handle a GET_ABOUT_ICON_GET_URL method call
 *
 * @param msg    The GET_ABOUT_ICON_GET_URL message
 * @param reply  The GET_ABOUT_ICON_GET_URL reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK if successfully handled
 *          - AJ_ERR_WRITE if there was a write failure
 */
AJ_Status AJ_AboutIconHandleGetURL(AJ_Message* msg, AJ_Message* reply);

/**
 * Handle a GET_ABOUT_ICON_GET_CONTENT method call
 *
 * @param msg    The GET_ABOUT_ICON_GET_CONTENT message
 * @param reply  The GET_ABOUT_ICON_GET_CONTENT reply message
 *
 * @return  Return AJ_Status
 *          - AJ_OK if successfully handled
 *          - AJ_ERR_WRITE if there was a write failure
 */
AJ_Status AJ_AboutIconHandleGetContent(AJ_Message* msg, AJ_Message* reply);

/**
 * Function called by the application and other services when there are changes that warrant sending
 * of a new announcement. The announce condition is cleared after all AJ_AboutAnnounce() is called.
 */
void AJ_AboutSetShouldAnnounce();

/**
 * Sets the announce flag on a list of objects
 *
 * @param objList  The object list to set.
 */
void AJ_AboutSetAnnounceObjects(AJ_Object* objList);

/**
 * @}
 */
#endif
