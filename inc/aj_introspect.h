#ifndef _AJ_INTROSPECT_H
#define _AJ_INTROSPECT_H
/**
 * @file aj_introspect.h
 * @defgroup aj_introspect Introspection Support
 * @{
 */
/******************************************************************************
 *  * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
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
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include "aj_target.h"
#include "aj_status.h"
#include "aj_bus.h"
#include "aj_msg.h"

/**
 * Support for introspection
 */

/**
 * An interface description is a NULL terminated array of strings. The first string is the interface
 * name. The subsequent strings are a compact representation of the members of the interface. In
 * this representation special characters encode information about the members, whitespace is
 * significant.
 *
 * If the first character of the interface name is a '$' character this indicates that the interface
 * is secure and only authenticated peers can make method calls and received signals defined in the
 * interface.  If the first character of the interface name is a '#' character this indicates that
 * security is not applicable to this interface even if the interface is implemented by an otherwise
 * secure object. The '$' and '#' characters are merely signifiers and are not part of the interface
 * name.
 *
 * The first character of a member string identifies the type of member:
 *
 * A '?' character indicates the member is a METHOD
 * A '!' character indicates the member is a SIGNAL
 * A '@' character indicates the member is a PROPERTY
 *
 * The type character is a signifier, it is not part of the member name. Characters following the
 * member type character up to the end of the string or to the first space character comprise the
 * member names. If the member is a METHOD or SIGNAL the remaining characters encode the argument
 * names, direction (IN or OUT) and the argument type as a standard AllJoyn signature string. For
 * SIGNALS for correctness the direction should be specified as OUT but it really doesn't matter as
 * the direction is ignored.
 *
 * Arguments are separated by a single space character. Argument names are optional and if present are
 * all characters between the space character and the directions character. All characters after the
 * direction character up to the next space or the end of the string are the argument type. The
 * argument direction is specified as follows:
 *
 * A '>' character indicates the argument is an OUT parameter.
 * A '<' character indicates the argument is an IN parameter.
 *
 * If the member is a PROPERTY the member name is terminated by an access rights character which is
 * immediately followed by the property type signature. The access rights for a property are
 * READ_ONLY, WRITE_ONLY and READ_WRITE. The access rights are specified as follows:
 *
 * A '>' character indicates the argument is READ_ONLY  (i.e. an OUT parameter)
 * A '<' character indicates the argument is WRITE_ONLY (i.e. an IN parameter)
 * A '=' character indicates the argument is READ/WRITE
 *
   @code

   static const char* const ExampleInterface[] = {
    "org.alljoyn.example",                  // The interface name
    "?StringPing inStr<s outStr>",          // A method called StringPing with an IN arg and OUT arg of type string
    "?Hello",                               // A method call with no arguments
    "?Add <i <i >i",                        // A method call that takes two integers and returns an integer. The args are not named
    "!ListChanged >a{ys}",                  // A signal that returns a dictionary
    "@TimeNow>(yyy)",                       // A READ_ONLY property that returns a struct with three 8 bit integers
    "@Counter=u",                           // A READ/WRITE property
    "@SecretKey<ay",                        // A WRITE_ONLY property that sets an array of bytes
    NULL                                    // End marker
   };

   @endcode

 *
 * This compact representation is expanded automatically into the very much more verbose XML form required to support introspection
 * requests.
 */

/**
 * Type for an interface description - NULL terminated array of strings.
 */
typedef const char* const* AJ_InterfaceDescription;


#define AJ_OBJ_FLAG_SECURE    0x01  /**< If set this bit indicates that an object is secure */
#define AJ_OBJ_FLAG_HIDDEN    0x02  /**< If set this bit indicates this is object is not announced */
#define AJ_OBJ_FLAG_DISABLED  0x04  /**< If set this bit indicates that method calls cannot be made to the object at this time */

/**
 * Type for an AllJoyn object description
 */
typedef struct _AJ_Object {
    const char* path;                               /**< object path */
    const AJ_InterfaceDescription* interfaces;      /**< interface descriptor */
    uint8_t flags;                                  /**< flags for the object */
} AJ_Object;


/*
 * Indicates that an identified member belongs to an application object
 */
#define AJ_BUS_ID_FLAG   0x00  /**< Built in bus object messages */
#define AJ_APP_ID_FLAG   0x01  /**< Application object messages */
#define AJ_PRX_ID_FLAG   0x02  /**< Proxy object messages */
#define AJ_SVC_ID_FLAG   0x04  /**< Service object messages */
#define AJ_REP_ID_FLAG   0x80  /**< Indicates a message is a reply message */

/*
 * Macros to encode a message id from the object path, interface, and member indices.
 */
#define AJ_BUS_MESSAGE_ID(p, i, m)  ((AJ_BUS_ID_FLAG << 24) | (((uint32_t)(p)) << 16) | (((uint32_t)(i)) << 8) | (m))       /**< Encode a message id from bus object */
#define AJ_APP_MESSAGE_ID(p, i, m)  ((AJ_APP_ID_FLAG << 24) | (((uint32_t)(p)) << 16) | (((uint32_t)(i)) << 8) | (m))       /**< Encode a message id from application object */
#define AJ_PRX_MESSAGE_ID(p, i, m)  ((AJ_PRX_ID_FLAG << 24) | (((uint32_t)(p)) << 16) | (((uint32_t)(i)) << 8) | (m))       /**< Encode a message id from proxy object */
#define AJ_SVC_MESSAGE_ID(p, i, m)  ((AJ_SVC_ID_FLAG << 24) | (((uint32_t)(p)) << 16) | (((uint32_t)(i)) << 8) | (m))       /**< Encode a message id from service object */
/*
 * Macros to encode a property id from the object path, interface, and member indices.
 */
#define AJ_BUS_PROPERTY_ID(p, i, m) AJ_BUS_MESSAGE_ID(p, i, m)      /**< Encode a property id from bus object */
#define AJ_APP_PROPERTY_ID(p, i, m) AJ_APP_MESSAGE_ID(p, i, m)      /**< Encode a property id from application object */
#define AJ_PRX_PROPERTY_ID(p, i, m) AJ_PRX_MESSAGE_ID(p, i, m)      /**< Encode a property id from proxy object */
#define AJ_SVC_PROPERTY_ID(p, i, m) AJ_SVC_MESSAGE_ID(p, i, m)      /**< Encode a property id from service object */

/**
 * Macro to generate the reply message identifier from method call message. This is the message
 * identifier in the reply context.
 */
#define AJ_REPLY_ID(id)  ((id) | (uint32_t)(AJ_REP_ID_FLAG << 24))

/**
 * Register the local objects and the remote objects for this application.  Local objects have
 * methods that remote applications can call, have properties that a remote application can GET or
 * SET or define signals that the local application can emit.  Proxy objects describe the remote
 * objects that have methods that this object can call and signals
 * that remote objects emit that this application can receive.
 *
 * @param localObjects  A NULL terminated array of object info structs.
 * @param proxyObjects  A NULL terminated array of object info structs.
 */
void AJ_RegisterObjects(const AJ_Object* localObjects, const AJ_Object* proxyObjects);

/**
 * This function checks that a message ifrom a remote peer is valid and correct and returns the
 * message id for that message.
 *
 * For method calls this function checks that the object is one of the registered objects, checks
 * that the interface and method are implemented by the object and checks that the signature is
 * correct.
 *
 * For signals this function checks that the interface is a known interface, the signal name is
 * defined for that interface, and the signature is correct.
 *
 * For method replies and error message this function matches the serial number of the response to
 * the serial number in the list of reply contexts. If the reply matches the signature is checked.
 *
 * If everything is correct the the message identifier is set in the message struct
 *
 * @param msg           The message to identify
 *
 * @return              Return AJ_Status
 */
AJ_Status AJ_IdentifyMessage(AJ_Message* msg);

/**
 * This function unmarshals the first two arguments of a property SET or GET message, identifies
 * which property the method is accessing and returns the id for the property.
 *
 * @param msg     The property GET or SET message to identify
 * @param propId  Returns the id for the identified property
 * @param sig     Buffer to fill in with the signature of the identified property
 * @param len     Length of the signature buffer
 *
 * @return   Return AJ_Status
 *         - ER_OK if the property was identified
 *         - AJ_ERR_NO_MATCH if there is no matching property
 *         - AJ_ERR_DISALLOWED if the property exists but has access rights do not permit the requested GET or SET operation.
 */
AJ_Status AJ_UnmarshalPropertyArgs(AJ_Message* msg, uint32_t* propId, char* sig, size_t len);

/**
 * This function marshals the first two arguments of a property SET or GET message.
 *
 * @param msg     The property GET or SET message to be initialized
 * @param propId  The the id for the specified property
 *
 * @return        Return AJ_Status
 */
AJ_Status AJ_MarshalPropertyArgs(AJ_Message* msg, uint32_t propId);

/**
 * Handle an introspection request
 *
 * @param msg        The introspection request method call
 * @param reply      The reply to the introspection request
 *
 * @return           Return AJ_Status
 */
AJ_Status AJ_HandleIntrospectRequest(const AJ_Message* msg, AJ_Message* reply);

/**
 * Internal function for initializing a message from information obtained via the message id.
 *
 * @param msg       The message to initialize
 * @param msgId     The message id
 * @param msgType   The type of the message
 *
 * @return          Return AJ_Status
 */
AJ_Status AJ_InitMessageFromMsgId(AJ_Message* msg, uint32_t msgId, uint8_t msgType, uint8_t* secure);

/**
 * Set or update the object path on a proxy object entry. This function makes is used for making
 * method calls to remote objects when the object path is not known until runtime. Note the proxy
 * object table cannot be declared as const in this case.
 *
 * @param proxyObjects  Pointer to the proxy object table (for validation purposes)
 * @param msgId         The message identifier for the methods
 * @param objPath       The object path to set. This value must remain valid while the method is
 *                      being marshaled.
 *
 * @return  - AJ_OK if the object path was sucessfully set.
 *          - AJ_ERR_OBJECT_PATH if the object path is NULL or invalid.
 *          - AJ_ERR_NO_MATCH if the message id does not identify a proxy object method call.
 */
AJ_Status AJ_SetProxyObjectPath(AJ_Object* proxyObjects, uint32_t msgId, const char* objPath);

/**
 * Internal function to allocate a reply context for a method call message. Reply contexts are used
 * to associate method replies with method calls. Depending on avaiable system resources the number
 * of reply contexts may be very limited, in some cases only one reply context.
 *
 * @param msg      A method call message that needs a reply context
 * @param timeout  The time to wait for a reply  (0 to use the internal default)
 *
 * @return   Return AJ_Status
 *         - AJ_OK if the reply context was allocated
 *         - AJ_ERR_RESOURCES if the reply context could not be allocated
 */
AJ_Status AJ_AllocReplyContext(AJ_Message* msg, uint32_t timeout);

/**
 * Internal function to release all reply contexts. Called when disconnecting from the bus.
 */
void AJ_ReleaseReplyContexts(void);

/**
 * Internal function to check for timed out method calls. Returns TRUE and sets some information in
 * the message struct to identify the timed-out call if there was one. This function is called by
 * AJ_UnmarshalMessage() when there are no messages to unmarshal.
 *
 * @param msg  A message structure to initialize if there was a timed-out method call.
 *
 * @return  Returns TRUE if there was a timed-out method call, FALSE otherwise.
 */
uint8_t AJ_TimedOutMethodCall(AJ_Message* msg);

/**
 * Internal function called to release a reply context in the case that a message could not be marshaled.
 *
 * @param msg  The message that a reply context might have been allocated for.
 */
void AJ_ReleaseReplyContext(AJ_Message* msg);

/**
 * Recursively set and/or clear the object flags on an application object and all the children of
 * the object. This function can be called to disable, hide, or secure and entire object tree. Note
 * that to use this funcion the application object list must not be declared as const.
 *
 * To disable an application object and all of its children recursively
 * @code
 * AJ_SetObjectFlags("/foo/bar", AJ_OBJ_FLAG_DISABLED, 0);
 * @endcode
 *
 * To enable an application object and all of its children recursively but leave them hidden
 * @code
 * AJ_SetObjectFlags("/foo/bar", AJ_OBJ_FLAG_HIDDEN, AJ_OBJ_FLAG_DISABLED);
 * @endcode
 *
 * @param objPath    The object path for the parent object to set the flags on
 * @param setFlags   The flags to set OR'd together
 * @param clearFlags The flags to clear OR'd together
 *
 * @return   Return AJ_Status
 *         - ER_OK if the flags were set
 *         - AJ_ERR_NO_MATCH if there are no matching objects
 */
AJ_Status AJ_SetObjectFlags(const char* objPath, uint8_t setFlags, uint8_t clearFlags);

/**
 * Debugging aid prints out the XML for an object table
 */
#ifdef NDEBUG
#define AJ_PrintXML(obj)
#else
void AJ_PrintXML(const AJ_Object* obj);
#endif

/**
 * Hook for unit testing marshal/unmarshal
 */
#ifndef NDEBUG
typedef AJ_Status (*AJ_MutterHook)(AJ_Message* msg, uint32_t msgId, uint8_t msgType);
#endif

/**
 * @}
 */
#endif