#!/usr/bin/env python
# Copyright (c) 2013-2014 AllSeen Alliance. All rights reserved.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import sys
import signal as sig
import logging
import types
import inspect
import collections
import random
from ctypes import *

class _AJ_Object(Structure):
    _fields_ = [("path", c_char_p),
                ("interfaces", POINTER(POINTER(c_char_p))),
                ("flags", c_ubyte)]

class _anon_rxtx(Union):
    #TODO function pointers
    _fields_ = [("send", c_void_p), #AJ_TxFunc funcptr
                ("recv", c_void_p)] #AJ_RxFunc funcptr

class _AJ_IOBuffer(Structure):
    _anonymous_ = ("anon_rxtx",)
    _fields_ = [("direction", c_ubyte),
                ("bufSize", c_uint16),
                ("bufStart", POINTER(c_ubyte)),
                ("readPtr", POINTER(c_ubyte)),
                ("writePtr", POINTER(c_ubyte)),
                ("anon_rxtx", _anon_rxtx),
                ("context", c_void_p)]

class _AJ_NetSocket(Structure):
    _fields_ = [("tx", _AJ_IOBuffer),
                ("rx", _AJ_IOBuffer)]

class _AJ_BusAttachment(Structure):
    _fields_ = [("uniqueName", c_char * 16),
                ("sock", _AJ_NetSocket),
                ("serial", c_uint32),
                ("pwdCallback", c_void_p)] # figure out func ptr

class _AJ_SessionOpts(Structure):
    _fields_ = [("traffic", c_ubyte),
                ("proximity", c_ubyte),
                ("transports", c_uint16),
                ("isMultipoint", c_uint32)]

class _val(Union):
    _fields_ = [("v_byte", POINTER(c_ubyte)),
                ("v_int16", POINTER(c_int16)),
                ("v_uint16", POINTER(c_uint16)),
                ("v_bool", POINTER(c_uint32)),
                ("v_uint32", POINTER(c_uint32)),
                ("v_int32", POINTER(c_int32)),
                ("v_int64", POINTER(c_int64)),
                ("v_uint64", POINTER(c_uint64)),
                ("v_double", POINTER(c_double)),
                ("v_string", c_char_p),
                ("v_objPath", c_char_p),
                ("v_signature", c_char_p),
                ("v_data", c_void_p)]

class _AJ_Arg(Structure):
    ARRAY_FLAG = 1

    scalars = {'b': (c_uint32, bool),
               'd': (c_double, None),
               'i': (c_int32, None),
               'n': (c_int16, None),
               'q': (c_uint16, None),
               't': (c_uint64, None),
               'u': (c_uint32, None),
               'x': (c_int64, None),
               'y': (c_ubyte, None),
               }

    strings = {'g': None,
               'o': None,
               's': None,
               }

    def __init__(self, typeId=None, value=None):
        self.clear()
        if typeId is not None:
            self.setValue(typeId, value)

    def clear(self):
        self.typeId = 0
        self.flags = 0
        self.len = 0
        self.storage = None
        self.value = None
        self.val.v_data = None
        self.val.sigPtr = None
        self.container = None

    def setValue(self, typeId, value):
        self.clear()

        if typeId in self.scalars:
            c_type, p_type = self.scalars[typeId]
            return self._setScalar(typeId, value, c_type, p_type)
        elif typeId in self.strings:
            return self._setString(typeId, value)
        else:
            return None
    def getValue(self):
        typeId = chr(self.typeId)
        if typeId in self.scalars:
            c_type, p_type = self.scalars[typeId]
            return self._getScalar(typeId, c_type, p_type)
        elif typeId in self.strings:
            return self._getString(typeId)

    def _setScalar(self, typeId, value, c_type, p_type):
        self.typeId = ord(typeId)

        if isinstance(value, collections.Iterable):
            if p_type:
                value = [p_type(v) for v in value]
            self.flags |= self.ARRAY_FLAG
            self.len = sizeof(c_type) * len(value)
            self.storage = (c_type * len(value))(*value)
            self.val.v_data = cast(self.storage, c_void_p)
        else:
            if p_type:
                value = p_type(value)
            self.storage = c_type(value)
            self.val.v_data = cast(pointer(self.storage), c_void_p)
    def _getScalar(self, typeId, c_type, p_type):
        if (self.typeId == ord(typeId)):
            if self.flags & self.ARRAY_FLAG:
                a = []
                for i in xrange(self.len / sizeof(c_type)):
                    value = cast(self.val.v_data, POINTER(c_type))[i]
                    if p_type:
                        value = p_type(value)
                    a.append(value)
                return a
            else:
                value = cast(self.val.v_data, POINTER(c_type)).contents.value
                if p_type:
                    value = p_type(value)
                return value
        else:
            return None


    def _setString(self, typeId, value):
        self.typeId = ord(typeId)
        self.len = len(value) + 1 # NUL termination
        self.storage = c_char_p(unicode(value))
        self.val.v_string = self.storage
    def _getString(self, typeId):
        if (self.typeId == ord(typeId)):
            return self.val.v_string
        else:
            return None

_AJ_Arg._fields_ = [("typeId", c_ubyte),
                   ("flags", c_ubyte),
                   ("len", c_uint16),
                   ("val", _val),
                   ("sigPtr", c_char_p),
                   ("container", POINTER(_AJ_Arg))]

class _AJ_MsgHeader(Structure):
    _fields_ = [("endianess", c_char),
                ("msgType", c_ubyte),
                ("flags", c_ubyte),
                ("majorVersion", c_ubyte),
                ("bodyLen", c_uint32),
                ("serialNum", c_uint32),
                ("headerLen", c_uint32)]

class _anon_pathserial(Union):
    _fields_ = [("objPath", c_char_p),
                ("replySerial", c_uint32)]

class _anon_membererror(Union):
    _fields_ = [("member", c_char_p),
                ("error", c_char_p)]

class _AJ_Message(Structure):
    _anonymous_ = ["anon_pathserial", "anon_membererror"]
    _fields_ = [("msgId", c_uint32),
                ("hdr", POINTER(_AJ_MsgHeader)),
                ("anon_pathserial", _anon_pathserial),
                ("anon_membererror", _anon_membererror),
                ("iface", c_char_p),
                ("sender", c_char_p),
                ("destination", c_char_p),
                ("signature", c_char_p),
                ("sessionId", c_uint32),
                ("timestamp", c_uint32),
                ("ttl", c_uint32),
                ("sigOffset", c_ubyte),
                ("varOffset", c_ubyte),
                ("bodyBytes", c_uint16),
                ("bus", POINTER(_AJ_BusAttachment)),
                ("outer", POINTER(_AJ_Arg))]

_PROPCALLBACK = CFUNCTYPE(c_int, POINTER(_AJ_Message), c_uint32, c_void_p)
propContext = {}

def _propGetCb(msg, propId, context):
    obj = propContext[context]
    handler, pm = obj.getProperties[propId]

    value = handler(obj)
    status, unused = _Marshal(msg.contents, value, pm.sig)

    return errormap[status]

_cPropGetCb = _PROPCALLBACK(_propGetCb)

def _propSetCb(msg, propId, context):
    obj = propContext[context]
    handler, pm = obj.setProperties[propId]

    value, status, unused = _Unmarshal(msg.contents, pm.sig)
    if status == 'OK':
        handler(obj, value)

    return errormap[status]

_cPropSetCb = _PROPCALLBACK(_propSetCb)

# Inputs are object path index, interface index, member index
def _PRX_MESSAGE_ID(p, i, m):
    PRX_ID_FLAG = 0x02
    return (PRX_ID_FLAG << 24) | (p << 16) | (i << 8) | m

def _APP_MESSAGE_ID(p, i, m):
    APP_ID_FLAG = 0x01
    return (APP_ID_FLAG << 24) | (p << 16) | (i << 8) | m

def _BUS_MESSAGE_ID(p, i, m):
    BUS_ID_FLAG = 0
    return (BUS_ID_FLAG << 24) | (p << 16) | (i << 8) | m

def _REPLY_ID(i):
    REP_ID_FLAG = 0x80
    return (REP_ID_FLAG << 24) | i

# Populate status in this module's namespace
def _gen_errormap():
    # TODO: Populate using AJ_StatusText()
    rawstatus = """\
    AJ_OK               = 0,  /**< Success status */
    AJ_ERR_NULL         = 1,  /**< Unexpected NULL pointer */
    AJ_ERR_UNEXPECTED   = 2,  /**< An operation was unexpected at this time */
    AJ_ERR_INVALID      = 3,  /**< A value was invalid */
    AJ_ERR_IO_BUFFER    = 4,  /**< An I/O buffer was invalid or in the wrong state */
    AJ_ERR_READ         = 5,  /**< An error while reading data from the network */
    AJ_ERR_WRITE        = 6,  /**< An error while writing data to the network */
    AJ_ERR_TIMEOUT      = 7,  /**< A timeout occurred */
    AJ_ERR_MARSHAL      = 8,  /**< Marshaling failed due to badly constructed message argument */
    AJ_ERR_UNMARSHAL    = 9,  /**< Unmarshaling failed due to a corrupt or invalid message */
    AJ_ERR_END_OF_DATA  = 10, /**< Not enough data */
    AJ_ERR_RESOURCES    = 11, /**< Insufficient memory to perform the operation */
    AJ_ERR_NO_MORE      = 12, /**< Attempt to unmarshal off the end of an array */
    AJ_ERR_SECURITY     = 13, /**< Authentication or decryption failed */
    AJ_ERR_CONNECT      = 14, /**< Network connect failed */
    AJ_ERR_UNKNOWN      = 15, /**< A unknown value */
    AJ_ERR_NO_MATCH     = 16, /**< Something didn't match */
    AJ_ERR_SIGNATURE    = 17, /**< Signature is not what was expected */
    AJ_ERR_DISALLOWED   = 18, /**< An operation was not allowed */
    AJ_ERR_FAILURE      = 19, /**< A failure has occurred */
    AJ_ERR_RESTART      = 20, /**< The OEM event loop must restart */
    AJ_ERR_LINK_TIMEOUT = 21, /**< The bus link is inactive too long */
    AJ_ERR_DRIVER       = 22, /**< An error communicating with a lower-layer driver */
    AJ_ERR_OBJECT_PATH  = 23, /**< Object path was not specified */
    AJ_ERR_BUSY         = 24, /**< An operation failed and should be retried later */
    AJ_ERR_DHCP         = 25, /**< A DHCP operation has failed */
    AJ_ERR_ACCESS       = 26, /**< The operation specified is not allowed */
    AJ_ERR_SESSION_LOST = 27, /**< The session was lost */
    AJ_ERR_LINK_DEAD    = 28, /**< The network link is now dead */
    AJ_ERR_HDR_CORRUPT  = 29, /**< The message header was corrupt */
    AJ_ERR_RESTART_APP  = 30, /**< The application must cleanup and restart */
    AJ_ERR_INTERRUPTED  = 31, /**< An I/O operation (READ) was interrupted */
    AJ_ERR_REJECTED     = 32, /**< The connection was rejected */
    AJ_ERR_RANGE        = 33, /**< Value provided was out of range */
    AJ_ERR_ACCESS_ROUTING_NODE = 34, /**< Access defined by routing node */
    AJ_ERR_KEY_EXPIRED  = 35, /**< The key has expired */
    AJ_ERR_SPI_NO_SPACE = 36, /**< Out of space error */
    AJ_ERR_SPI_READ     = 37, /**< Read error */
    AJ_ERR_SPI_WRITE    = 38, /**< Write error */
    AJ_ERR_OLD_VERSION  = 39, /**< Router you connected to is old and unsupported */
    AJ_ERR_NVRAM_READ   = 40, /**< Error while reading from NVRAM */
    AJ_ERR_NVRAM_WRITE  = 41, /**< Error while writing to NVRAM */
"""

    errors = {}
    for s in rawstatus.splitlines():
        parts = s.split()
        errname = parts[0].replace("AJ_", "")
        errvalue = int(parts[2].strip(','))
        errors[errname] = errvalue
        errors[errvalue] = errname
        #globals()[errname] = errvalue
    return errors

def _gen_msgmap():
    msgtypes = ['INVALID',
                'METHOD_CALL',
                'METHOD_REG',
                'ERROR',
                'SIGNAL']
    msgmap = {}
    for i, t in enumerate(msgtypes):
        msgmap[i] = t
        msgmap[t] = i

    return msgmap

def _setup_prototypes(lib):
    lib.AJ_Initialize.restype = None
    lib.AJ_Initialize.argtypes = ()

    lib.AJ_PrintXML.restype = None
    lib.AJ_PrintXML.argtypes = (POINTER(_AJ_Object),)

    lib.AJ_StartClient.argtypes = (POINTER(_AJ_BusAttachment),
                                   c_char_p,
                                   c_uint32,
                                   c_uint8,
                                   c_char_p,
                                   c_uint16,
                                   POINTER(c_uint32),
                                   POINTER(_AJ_SessionOpts))
    lib.AJ_StartClient.restype = c_uint

    lib.AJ_MarshalMethodCall.argtypes = (POINTER(_AJ_BusAttachment),
                                         POINTER(_AJ_Message),
                                         c_uint32,
                                         c_char_p,
                                         c_uint32,
                                         c_ubyte,
                                         c_uint32)
    lib.AJ_MarshalMethodCall.restype = c_uint

    lib.AJ_MarshalArgs.restype = c_uint
    #lib.AJ_MarshalArgs.argtypes = varargs

    lib.AJ_UnmarshalArgs.restype = c_uint
    #lib.AJ_UnmarshalArgs.argtypes = varargs

    lib.AJ_DeliverMsg.argtypes = (POINTER(_AJ_Message),)
    lib.AJ_DeliverMsg.restype = c_uint

    lib.AJ_UnmarshalMsg.argtypes = (POINTER(_AJ_BusAttachment),
                                    POINTER(_AJ_Message),
                                    c_uint32)
    lib.AJ_UnmarshalMsg.restype = c_uint

    lib.AJ_UnmarshalArg.argtypes = (POINTER(_AJ_Message),
                                    POINTER(_AJ_Arg))
    lib.AJ_UnmarshalArg.restype = c_uint

    lib.AJ_MarshalArg.argtypes = (POINTER(_AJ_Message),
                                  POINTER(_AJ_Arg))
    lib.AJ_MarshalArg.restype = c_uint

    lib.AJ_StartService.argtypes = (POINTER(_AJ_BusAttachment),
                                    c_char_p,
                                    c_uint32,
                                    c_uint8,
                                    c_uint16,
                                    c_char_p,
                                    c_uint32,
                                    POINTER(_AJ_SessionOpts))
    lib.AJ_StartService.restype = c_uint

    lib.AJ_MarshalReplyMsg.argtypes = (POINTER(_AJ_Message),
                                       POINTER(_AJ_Message))
    lib.AJ_MarshalReplyMsg.restype = c_uint

    lib.AJ_InitArg.argtypes = (POINTER(_AJ_Arg),
                               c_ubyte,
                               c_ubyte,
                               c_void_p,
                               c_size_t)
    lib.AJ_InitArg.restype = c_uint

    lib.AJ_BusReplyAcceptSession.argtypes = (POINTER(_AJ_Message),
                                             c_uint32)
    lib.AJ_BusReplyAcceptSession.restype = c_uint

    lib.AJ_MarshalContainer.argtypes = (POINTER(_AJ_Message),
                                        POINTER(_AJ_Arg),
                                        c_ubyte)
    lib.AJ_MarshalContainer.restype = c_uint

    lib.AJ_MarshalCloseContainer.argtypes = (POINTER(_AJ_Message),
                                             POINTER(_AJ_Arg))
    lib.AJ_MarshalCloseContainer.restype = c_uint

    lib.AJ_UnmarshalContainer.argtypes = (POINTER(_AJ_Message),
                                          POINTER(_AJ_Arg),
                                          c_ubyte)
    lib.AJ_UnmarshalContainer.restype = c_uint

    lib.AJ_UnmarshalCloseContainer.argtypes = (POINTER(_AJ_Message),
                                               POINTER(_AJ_Arg))
    lib.AJ_UnmarshalCloseContainer.restype = c_uint

    lib.AJ_MarshalPropertyArgs.argtypes = (POINTER(_AJ_Message),
                                           c_uint32)
    lib.AJ_MarshalPropertyArgs.restype = c_uint

    lib.AJ_UnmarshalPropertyArgs.argtype = (POINTER(_AJ_Message),
                                            POINTER(c_uint32),
                                            c_char_p,
                                            c_size_t)
    lib.AJ_UnmarshalPropertyArgs.restype = c_uint

    lib.AJ_BusPropGet.argtype = (POINTER(_AJ_Message),
                                 _PROPCALLBACK,
                                 c_void_p)
    lib.AJ_BusPropGet.restype = c_uint

    lib.AJ_BusPropSet.argtype = (POINTER(_AJ_Message),
                                 _PROPCALLBACK,
                                 c_void_p)
    lib.AJ_BusPropSet.restype = c_uint

    lib.AJ_BusSetSignalRule.argtype = (POINTER(_AJ_BusAttachment),
                                       c_char_p,
                                       c_uint8)
    lib.AJ_BusSetSignalRule.restype = c_uint

def _list_to_array(datatype, l):
    if l is None:
        return None
    arraytype = datatype * len(l)
    return arraytype(*l)

def _list_to_terminated_array(datatype, l):
    return _list_to_array(datatype, l + [None])

def _byref_class(obj, cls):
    if isinstance(obj, _wrappedStructure) and isinstance(obj, cls):
        return byref(obj._struct)
    elif obj is not None:
        logging.error("Not a %s: %s" % (cls.__name__, obj))

    return None

class _wrappedStructure(object):
    def __init__(self, struct):
        self._struct = struct

class Variant(object):
    typeMap = {str: 's',
               unicode: 's',
               bool: 'b',
               float: 'd',
               int: 'i',
               long: 'x'}

    def __init__(self, value, signature=None):
        if signature is None:
            self.signature = self._inferSignature(value)
        else:
            self.signature = signature

        if self.signature is None:
            self.value = None
        else:
            self.value = value

    def __repr__(self):
        return '<AJ.Variant signature=%s value=%s>' % (repr(self.signature), repr(self.value))

    def isEmpty(self):
        return self.value is None

    def _inferContainer(self, value):
        if isinstance(value, types.StringTypes):
            container = None
        elif isinstance(value, Variant):
            container = 'variant'
        elif isinstance(value, dict):
            container = 'dict'
        else:
            try:
                vtypes = set([type(v) for v in value])
                if len(vtypes) <= 1:
                    # Includes empty iterables
                    container = 'array'
                else:
                    container = 'struct'
            except TypeError:
                container = None

        return container

    def _inferSignature(self, value):
        container = self._inferContainer(value)

        # Generate signature for each container
        if container is None:
            return self.typeMap.get(type(value))
        elif container == 'variant':
            return 'v'
        elif container == 'array':
            if len(value) == 0:
                # Can't determine signature of empty array
                return None
            itemtype = self.typeMap.get(type(value[0]))
            if itemtype is None:
                return None
            else:
                return 'a' + itemtype
        elif container == 'struct':
            itemsigs = [self._inferSignature(v) for v in value]
            if None in itemsigs:
                return None
            else:
                return "(%s)" % ''.join(itemsigs)
        elif container == 'dict':
            ktypes = set([type(k) for k in value.iterkeys()])
            if len(ktypes) != 1:
                # Invalid dict - can't infer key type if no keys, or multiple key types
                return None
            ktype = self.typeMap.get(list(ktypes)[0])
            valueSigs = set([self._inferSignature(v) for v in value.itervalues()])
            if None in valueSigs:
                # One or more values had a non-inferrable signature, inference has failed
                return None

            if len(valueSigs) == 1:
                valueSig = list(valueSigs)[0]
            else:
                valueSig = 'v'

            return "a{%s%s}" % (ktype, valueSig)

_basicTypes = 'bdginoqstuxy'
_scalarTypes = 'bdinqtuxy'

def _Marshal(msg, argvalue, argtype):
    logging.debug("_Marshal(msg, %s, %s)", repr(argvalue), repr(argtype))
    if argtype[0] in _basicTypes:
        arg = _AJ_Arg(argtype[0], argvalue)
        logging.debug("AJ_MarshalArg (basic)")
        status = _ajlib.AJ_MarshalArg(byref(msg), byref(arg))
        if errormap[status] != 'OK':
            logging.error("MarshalArg failure: %s", errormap[status])
        argtype = argtype[1:]

    elif argtype[0] == 'a' and len(argtype) > 1:
        # Array. Marshal a series of same-type values in to an array container.
        # Dictionaries have special handling to pass each key/value pair
        # for struct-like marshaling
        arrayArg = _AJ_Arg()
        logging.debug("AJ_MarshalContainer (array)")
        status = _ajlib.AJ_MarshalContainer(byref(msg), byref(arrayArg), ord('a'))
        if errormap[status] != 'OK':
            logging.error("Array MarshalContainer failure: %s", errormap[status])
        itemtype = argtype[1:]

        if (itemtype[0] == '{'):
            values = argvalue.iteritems()
        else:
            values = argvalue

        for v in values:
            status, argtype = _Marshal(msg, v, itemtype)
            if status != 'OK':
                logging.error("Array MarshalArg failure: %s", status)
        logging.debug("AJ_MarshalCloseContainer (array)")
        status = _ajlib.AJ_MarshalCloseContainer(byref(msg), byref(arrayArg))
        if errormap[status] != 'OK':
            logging.error("Array MarshalCloseContainer failure: %s", errormap[status])

    elif argtype[0] == '(':
        # Struct. Marshal a list of values in to a struct container.
        structArg = _AJ_Arg()
        logging.debug("AJ_MarshalContainer (struct)")
        status = _ajlib.AJ_MarshalContainer(byref(msg), byref(structArg), ord('('))
        if errormap[status] != 'OK':
            logging.error("Struct MarshalContainer failure: %s", errormap[status])
        argtype = argtype[1:]
        while argvalue and argtype and argtype[0] != ')':
            status, argtype = _Marshal(msg, argvalue.pop(0), argtype)
            if status != 'OK':
                logging.error("Struct MarshalArg failure: %s", errormap[status])
        logging.debug("AJ_MarshalCloseContainer (struct)")
        status = _ajlib.AJ_MarshalCloseContainer(byref(msg), byref(structArg))
        argtype = argtype[1:]
        if errormap[status] != 'OK':
            logging.error("Struct MarshalCloseContainer failure: %s", errormap[status])

    elif argtype[0] == '{':
        # Dictionary key/value pair. Key must be a basic type, value not restricted.
        # Since a dictionary type signature looks like "a{<something>}",
        # the array aspect of the dictionary is handled by the caller.
        # This code is only responsible for marshaling one key/value pair.
        dictArg = _AJ_Arg()
        logging.debug("AJ_MarshalContainer (dict item)")
        status = _ajlib.AJ_MarshalContainer(byref(msg), byref(dictArg), ord('{'))
        if errormap[status] != 'OK':
            logging.error("Dict MarshalContainer failure: %s", errormap[status])
        argtype = argtype[1:]

        if argtype[0] not in _basicTypes:
            logging.error("Dict Marshal failure: key not a basic type: " % argtype[0])

        status, argtype = _Marshal(msg, argvalue[0], argtype)

        if status != 'OK':
            logging.error("Dict Marshal key failure: %s", status)

        status, argtype = _Marshal(msg, argvalue[1], argtype)

        if status != 'OK':
            logging.error("Dict Marshal value failure: %s", status)

        logging.debug("AJ_MarshalCloseContainer (dict item)")
        status = _ajlib.AJ_MarshalCloseContainer(byref(msg), byref(dictArg))
        if errormap[status] != 'OK':
            logging.error("Struct MarshalCloseContainer failure: %s", errormap[status])

        if argtype[0] != '}':
            logging.error("Dict type does not end with '}'")

        argtype = argtype[1:]

    elif argtype[0] == 'v':
        # Variant. Value can be wrapped in a Variant object in order to get the
        # type signature.
        # Some python types will be automatically inferred from the value:
        # str = 's'
        # bool = 'b'
        # float = 'd'
        # int = 'i'
        # long = 'x'
        # If the value is a dictionary, it will be inferred as a dictionary (with variant value if values are not of same type)
        # If the value is an iterable with values of the same type, it is inferred as an array
        # If the value is an iterable with values of different types, it is inferred as a struct

        if not isinstance(argvalue, Variant):
            argvalue = Variant(argvalue)

        logging.debug("AJ_MarshalVariant")
        status = _ajlib.AJ_MarshalVariant(byref(msg), argvalue.signature)
        if errormap[status] != 'OK':
            logging.error("MarshalVariant failure: %s", errormap[status])

        status, unused = _Marshal(msg, argvalue.value, argvalue.signature)
        if status != 'OK':
            logging.error("MarshalVariant failure: %s", status)

        argtype = argtype[1:]
    else:
        logging.error("Unknown type signature, marshal failed: %s" % argtype)
        argtype = ''

    return ('OK', argtype)

def _Unmarshal(msg, signature):
    logging.debug("_Unmarshal(msg, %s)", repr(signature))
    if signature[0] in _basicTypes:
        arg = _AJ_Arg()
        logging.debug("AJ_UnmarshalArg (basic)")
        status = _ajlib.AJ_UnmarshalArg(byref(msg), byref(arg))
        if errormap[status] not in ('OK', 'ERR_NO_MORE'):
            logging.error("Basic unmarshal failure: %s", errormap[status])
        signature = signature[1:]
        item = arg.getValue()
        status = errormap[status]
        logging.debug("Got basic value: %s", repr(item))

    elif signature[0] == 'a':
        # Array. Unmarshal a series of same-type values in to a list.
        arrayArg = _AJ_Arg()
        itemtype = signature[1:]

        if itemtype[0] in _scalarTypes:
            # Arrays of scalars are fully unmarshaled with the container
            logging.debug("AJ_UnmarshalArg (scalar array)")
            status = _ajlib.AJ_UnmarshalArg(byref(msg), byref(arrayArg))
            if errormap[status] not in ('OK', 'ERR_NO_MORE'):
                logging.error("Basic unmarshal failure: %s", errormap[status])

            item = arrayArg.getValue()
            signature = itemtype[1:]
        else:
            # Other types need to be recursively unmarshaled
            logging.debug("AJ_UnmarshalContainer (array)")
            status = _ajlib.AJ_UnmarshalContainer(byref(msg), byref(arrayArg), ord('a'));
            if errormap[status] != 'OK':
                logging.error("Array UnmarshalContainer failure: %s", errormap[status])

            if (itemtype[0] == '{'):
                # Dictionary
                item = {}
            else:
                # Normal array
                item = []

            status = 'OK'
            while status == 'OK':
                element, status, signature = _Unmarshal(msg, itemtype)
                if status == 'OK':
                    if type(item) == dict:
                        # element is a dict with one key/value pair, add it to item
                        item.update(element)
                    else:
                        # element is a list, append the new element
                        item.append(element)

            if status not in ('OK', 'ERR_NO_MORE'):
                logging.error("Array unmarshal failure: %s" % status)

            logging.debug("AJ_UnmarshalCloseContainer (array)")
            status = _ajlib.AJ_UnmarshalCloseContainer(byref(msg), byref(arrayArg))
            if errormap[status] != 'OK':
                logging.error("Array unmarshal close failure: %s" % errormap[status])

        status = errormap[status]

    elif signature[0] == '(':
        # Struct. Unmarshal in to a list of values of various types.
        structArg = _AJ_Arg()
        signature = signature[1:]

        logging.debug("AJ_UnmarshalContainer (struct)")
        status = _ajlib.AJ_UnmarshalContainer(byref(msg), byref(structArg), ord('('))

        if errormap[status] != 'OK':
            logging.error("Struct unmarshal failure: %s" % errormap[status])

        item = []
        status = 'OK'
        while status == 'OK' and signature[0] != ')':
            element, status, signature = _Unmarshal(msg, signature)

            if status == 'OK':
                item.append(element)

        logging.debug("AJ_UnmarshalCloseContainer (struct)")
        status = _ajlib.AJ_UnmarshalCloseContainer(byref(msg), byref(structArg))
        if errormap[status] != 'OK':
            logging.error("Struct unmarshal close failure: %s" % errormap[status])

        status = errormap[status]

    elif signature[0] == '{':
        # Dictionary key/value pair. Unmarshal the key and the value.
        dictArg = _AJ_Arg()
        signature = signature[1:]

        logging.debug("AJ_UnmarshalContainer (dict)")
        status = _ajlib.AJ_UnmarshalContainer(byref(msg), byref(dictArg), ord('{'))

        if errormap[status] == 'ERR_NO_MORE':
            return ({}, errormap[status], '')
        if errormap[status] != 'OK':
            logging.error("Dict unmarshal failure: %s" % errormap[status])

        key, status, signature = _Unmarshal(msg, signature)
        if status != 'OK':
            logging.error("Dict key unmarshal failure: %s" % errormap[status])
        value, status, signature = _Unmarshal(msg, signature)
        if status != 'OK':
            logging.error("Dict value unmarshal failure: %s" % errormap[status])

        # Consume '}'
        signature = signature[1:]

        logging.debug("AJ_UnmarshalCloseContainer (dict)")
        status = _ajlib.AJ_UnmarshalCloseContainer(byref(msg), byref(dictArg))
        if errormap[status] != 'OK':
            logging.error("Dict unmarshal close failure: %s" % errormap[status])

        item = {key: value}
        status = errormap[status]

    elif signature[0] == 'v':
        # Variant.
        varsig = c_char_p()
        logging.debug("AJ_UnmarshalVariant")
        status = _ajlib.AJ_UnmarshalVariant(byref(msg), byref(varsig))
        if errormap[status] != 'OK':
            logging.error("Variant container unmarshal failure: %s" % errormap[status])
        logging.debug("Variant signature: %s", varsig.value)
        value, status, unused = _Unmarshal(msg, varsig.value)
        if status != 'OK':
            logging.error("Variant data unmarshal failure: %s" % errormap[status])
        item = Variant(value, varsig.value)

    logging.debug("item=%s status=%s signature=%s", repr(item), repr(status), repr(signature))
    return (item, status, signature)

# Exposed functions
def Initialize():
    return _ajlib.AJ_Initialize()

def PrintXML(obj):
    _ajlib.AJ_PrintXML(_byref_class(obj, Object))

# Exposed classes
class BusAttachment(_wrappedStructure):
    def __init__(self):
        super(BusAttachment, self).__init__(_AJ_BusAttachment())
        self.sessionId = None
        self.localPyObjects = None
        self.localCObjects = None
        self.proxyPyObjects = None
        self.proxyCObjects = None
        self.messageIds = {}
        self.loopRunning = False
        self.loopQuitPending = False

    def startClient(self, daemonName, timeout, connected, name, port, opts):
        self.name = name
        sessionId = c_uint32()
        status = _ajlib.AJ_StartClient(byref(self._struct), daemonName, timeout, connected,
                                       name, port, byref(sessionId), _byref_class(opts, SessionOpts))
        self.sessionId = sessionId.value
        return errormap[status]

    def startService(self, daemonName, timeout, connected, name, port, opts):
        AJ_NAME_REQ_DO_NOT_QUEUE = 4
        self.name = name
        status = _ajlib.AJ_StartService(byref(self._struct), daemonName, timeout, connected,
                                        port, name, AJ_NAME_REQ_DO_NOT_QUEUE, _byref_class(opts, SessionOpts))
        return errormap[status]

    def registerObjects(self, localObjects, proxyObjects):
        """Assign object indexes and call AJ_RegisterObjects.
        Reference the python objects so they are not deleted, and keep the C arrays alive because the AJ
        library keeps pointers to them."""
        if localObjects is not None:
            for i, o in enumerate(localObjects):
                o.index = i
                o.isProxy = False
                self.messageIds.update(o._getMethodIds())
                self.messageIds.update(o._getSignalIds())
                o._setupPropertyIds()
            ajLocal = [o._struct for o in localObjects]
            ajLocal.append(_AJ_Object(None, None, 0))
            self.localPyObjects = localObjects[:]
            self.localCObjects = _list_to_array(_AJ_Object, ajLocal)

        if proxyObjects is not None:
            for i, o in enumerate(proxyObjects):
                o.index = i
                o.isProxy = True
                self.messageIds.update(o._getSignalIds())
            ajProxy = [o._struct for o in proxyObjects]
            ajProxy.append(_AJ_Object(None, None, 0))
            self.proxyPyObjects = proxyObjects[:]
            self.proxyCObjects = _list_to_array(_AJ_Object, ajProxy)

        _ajlib.AJ_RegisterObjects(self.localCObjects, self.proxyCObjects)

    def enableSessionlessSignals(self):
        logging.debug("Enabling sessionless signal reception")
        logging.debug("AJ_BusSetSignalRule")
        _ajlib.AJ_BusSetSignalRule(byref(self._struct), "sessionless='t'", 0)

    def quitLoop(self):
        logging.debug("Quit loop")
        if not self.loopRunning:
            return False

        self.loopQuitPending = True
        return True

    def processMessages(self, iterations=0, replyId=None, replyArgs=None, replyValues=None):
        logging.debug("processMessages")
        if not (replyId == replyArgs == replyValues == None) and None in (replyId, replyArgs, replyValues):
            logging.error("Incomplete reply information")
            return

        self.loopRunning = True
        self.loopQuitPending = False
        status = 'OK'
        done = False
        msg = _AJ_Message()
        while not done and not self.loopQuitPending:
            if iterations > 0:
                if iterations == 1:
                    self.loopQuitPending = True
                iterations -= 1

            status = _ajlib.AJ_UnmarshalMsg(byref(self._struct), byref(msg), 1000*5)

            if errormap[status] == 'ERR_TIMEOUT':
                continue
            elif errormap[status] == 'OK':
                logging.debug("Received message with id=%08x", msg.msgId)
                if msg.msgId == _BUS_MESSAGE_ID(2, 0, 0):
                    logging.debug("Accept Session")
                    signature = "qus"
                    args = []
                    status = 'OK'
                    while signature and status == 'OK':
                        arg, status, signature = _Unmarshal(msg, signature)
                        args.append(arg)
                    if status == 'OK':
                        _ajlib.AJ_BusReplyAcceptSession(byref(msg), True)
                elif msg.msgId == replyId:
                    logging.debug("Reply")
                    if msg.hdr.contents.msgType == msgmap['ERROR']:
                        status = 'FAILURE'
                    else:
                        for argname, signature in replyArgs:
                            item, status, signature = _Unmarshal(msg, signature)
                            if status != 'OK':
                                logging.error("UnmarshalArg failure: %s", status)
                                _ajlib.AJ_CloseMsg(byref(msg))
                                break

                            replyValues.append(item)
                    done = True
                elif msg.msgId in self.messageIds:
                    logging.debug("Registered message ID")
                    obj, methodobj, member = self.messageIds[msg.msgId]

                    if methodobj.aj_raw:
                        # Raw methods handle their own marshaling/unmarshaling
                        methodobj(obj, msg)
                    else:
                        # Normal calls are handled here
                        args = [obj]
                        for argname, signature in member.inArgs:
                            item, status, signature = _Unmarshal(msg, signature)
                            if status != 'OK':
                                logging.error("UnmarshalArg failure: %s" % status)
                                _ajlib.AJ_CloseMsg(byref(msg))
                            args.append(item)

                        # Call object method
                        logging.debug("Calling %s(*%s)", member.name, args)
                        outArgs = methodobj(*args)

                        # Send reply for method calls
                        if isinstance(member, MethodMember):
                            if isinstance(outArgs, types.StringTypes) or not isinstance(outArgs, collections.Iterable):
                                # Method returned a string or non-iterable. Making a single-item list
                                # so the output argument is marshaled correctly.
                                outArgs = [outArgs]

                            reply = _AJ_Message()
                            logging.debug("AJ_MarshalReplyMsg")
                            _ajlib.AJ_MarshalReplyMsg(byref(msg), byref(reply))

                            outTypes = [m[1] for m in member.outArgs]
                            for argvalue, argtype in zip(outArgs, outTypes):
                                status, unused = _Marshal(reply, argvalue, argtype)
                                if status != 'OK':
                                    logging.error("Marshal failure: %s" % status)
                            logging.debug("Sending reply message with id=%08x", msg.msgId)
                            _ajlib.AJ_DeliverMsg(byref(reply))
                else:
                    logging.debug("Bus Message")
                    status = _ajlib.AJ_BusHandleBusMessage(byref(msg))
                    if errormap[status] != 'OK':
                        logging.error("BusMessage failed: %s" % errormap[status])

            _ajlib.AJ_CloseMsg(byref(msg))

        loopQuitPending = False
        loopRunning = False
        return status

class SessionOpts(_wrappedStructure):
    def __init__(self):
        super(SessionOpts, self).__init__(_AJ_SessionOpts())

class Interface(object):
    def __init__(self, name, memberlist):
        self.name = name
        self.memberlist = memberlist
        self.members = {}
        self.methods = {}
        self.signals = {}
        self.properties = {}

        for i, m in enumerate(self.memberlist):
            m.index = i
            self.members[m.name] = m
            if isinstance(m, MethodMember):
                self.methods[m.name] = m
            if isinstance(m, SignalMember):
                self.signals[m.name] = m
            if isinstance(m, PropertyMember):
                self.properties[m.name] = m

    def toStringList(self, indent=0):
        return [' ' * indent + self.name] + [m.toString(indent*2) for m in self.memberlist]

    def toString(self, indent=0):
        return '\n'.join(self.toStringList(indent))

class InterfaceMember(object):
    def __init__(self):
        self.index = None # Populated at registration time

class MethodMember(InterfaceMember):
    def __init__(self, name, inArgs=[], outArgs=[]):
        super(MethodMember, self).__init__()
        self.name = name
        self.inArgs = inArgs
        self.outArgs = outArgs

        # Create maps of arg names to method indexes
        self.inMap = {}
        if self.inArgs:
            for i, a in enumerate(self.inArgs):
                self.inMap[a[0]] = i
        self.outMap = {}
        if self.outArgs:
            for i, a in enumerate(self.outArgs):
                self.outMap[a[0]] = i

    def toString(self, indent=0):
        args = []
        if self.inArgs:
            args.extend(["%s<%s" % a for a in self.inArgs])
        if self.outArgs:
            args.extend(["%s>%s" % a for a in self.outArgs])
        return ("%s?%s %s" % (' ' * indent, self.name, ' '.join(args))).rstrip()

class SignalMember(InterfaceMember):
    def __init__(self, name, args=None):
        super(SignalMember, self).__init__()
        self.name = name
        self.inArgs = args

    def toString(self, indent=0):
        args = []
        if self.inArgs:
            args.extend(["%s>%s" % a for a in self.inArgs])
        return ("%s!%s %s" % (' ' * indent, self.name, ' '.join(args))).rstrip()

class PropertyMember(InterfaceMember):
    def __init__(self, name, sig, rights='r'):
        super(PropertyMember, self).__init__()
        self.name = name
        self.sig = sig
        self.rights = rights

    def toString(self, indent=0):
        rightsmap = {'rw': '=', 'r': '>', 'w': '<'}
        return "%s@%s%s%s" % (' ' * indent, self.name, rightsmap[self.rights], self.sig)

PropertiesInterface = Interface('org.freedesktop.DBus.Properties',
                                [MethodMember(name='Get',
                                              inArgs=[('interface_name', 's'), ('property_name', 's')],
                                              outArgs=[('value', 'v')]),
                                 MethodMember(name='Set',
                                              inArgs=[('interface_name', 's'), ('property_name', 's'), ('value', 'v')]),
                                 MethodMember(name='GetAll',
                                              inArgs=[('interface_name', 's')],
                                              outArgs=[('values', 'a{sv}')]),
                                 ])

class method(object):
    """Decorator for class methods"""
    def __init__(self, interface, name=None, raw=False):
        """Called to construct decorator, capture decorator args here"""
        self.interface = interface
        self.name = name
        self.raw = raw

    def __call__(self, func):
        """Called one time, immediately after constructor. Return a function object."""
        def wrapped_method(*args, **kwargs):
            """This will run every time the method is called"""
            logging.debug("wrapped_method(%s, %s)", repr(args), repr(kwargs))

            ajobj = args[0]

            mm = ajobj.interfaces[self.interface].methods[self.name]
            callargs = {}

            positional = args[1:]
            if len(positional) > len(mm.inArgs):
                logger.warning("Too many positional args, truncating")
                positional = positional[:len(mm.inArgs)]
            # Map positional args to names
            for i, a in enumerate(positional):
                callargs[mm.inArgs[i][0]] = a

            # Map keyword args
            callargs.update(kwargs)

            listargs = [None] * len(mm.inArgs)
            for i, a in enumerate(mm.inArgs):
                try:
                    listargs[i] = (callargs[a[0]], a[1]) # (value, type)
                except KeyError:
                    logging.error('Input argument "%s" not supplied for %s', a[0], self.name)
                    raise

            msg = _AJ_Message()
            msgId = _PRX_MESSAGE_ID(ajobj.index, ajobj.interfaceIndex[self.interface], mm.index)
            flags = 0
            timeout = 100*10

            status = "ERR_RESOURCES"
            while status == "ERR_RESOURCES":
                logging.debug("AJ_MarshalMethodCall")
                status = _ajlib.AJ_MarshalMethodCall(byref(ajobj.bus._struct), byref(msg), msgId,
                                                     ajobj.bus.name, ajobj.bus.sessionId, flags, timeout)
                status = errormap[status]

                if status == "ERR_RESOURCES":
                    ajobj.bus.processMessages(1)

            if status != 'OK':
                logging.error("MarshalMethodCall failure: %s", errormap[status])
                return

            for argvalue, argtype in listargs:
                status, unused = _Marshal(msg, argvalue, argtype)

            logging.debug("Sending method call message with id=%08x", msg.msgId)
            status = _ajlib.AJ_DeliverMsg(byref(msg))

            if errormap[status] != 'OK':
                logging.error("DeliverMsg failure: %s", errormap[status])
                return None

            returnVal = []
            ajobj.bus.processMessages(replyId=_REPLY_ID(msgId), replyArgs=mm.outArgs, replyValues=returnVal)

            return returnVal

        if self.name is None:
            self.name = func.__name__

        func.aj_raw = self.raw

        if self.raw:
            decoratedFunc = func
        else:
            decoratedFunc = wrapped_method
        decoratedFunc.aj_name = self.name
        decoratedFunc.aj_method = True
        decoratedFunc.aj_interface = self.interface
        decoratedFunc.aj_handler = func
        return decoratedFunc

class signal(object):
    """Decorator for class methods"""
    def __init__(self, interface, name=None, raw=False):
        """Called to construct decorator, capture decorator args here"""
        self.interface = interface
        self.name = name
        self.raw = raw

    def __call__(self, func):
        """Called one time, immediately after constructor. Return a function object."""
        def wrapped_signal(*args, **kwargs):
            """This will run every time the signal is called"""
            logging.debug("wrapped_signal(%s, %s)", repr(args), repr(kwargs))

            ajobj = args[0]

            if ajobj.isProxy:
                # For proxy objects, send a directed signal
                broadcast = False
            else:
                # For local objects, send a broadcast signal
                broadcast = True

            sm = ajobj.interfaces[self.interface].signals[self.name]
            callargs = {}

            positional = args[1:]
            if len(positional) > len(sm.inArgs):
                logger.warning("Too many positional args, truncating")
                positional = positional[:len(sm.inArgs)]
            # Map positional args to names
            for i, a in enumerate(positional):
                callargs[sm.inArgs[i][0]] = a

            # Map keyword args
            callargs.update(kwargs)

            listargs = [None] * len(sm.inArgs)
            for i, a in enumerate(sm.inArgs):
                listargs[i] = (callargs[a[0]], a[1]) # (value, type)

            msg = _AJ_Message()
            ttl = 0

            if broadcast:
                msgId = _APP_MESSAGE_ID(ajobj.index, ajobj.interfaceIndex[self.interface], sm.index)
                flags = 0x10 # AJ_FLAG_SESSIONLESS
                destination = None
                sessionId = 0
            else:
                msgId = _PRX_MESSAGE_ID(ajobj.index, ajobj.interfaceIndex[self.interface], sm.index)
                flags = 0
                destination = ajobj.bus.name
                sessionId = ajobj.bus.sessionId

            logging.debug("AJ_MarshalSignal")
            status = _ajlib.AJ_MarshalSignal(byref(ajobj.bus._struct), byref(msg), msgId,
                                             destination, sessionId, flags, ttl)
            if errormap[status] != 'OK':
                logging.error("MarshalSignal failure: %s", errormap[status])
                return

            for argvalue, argtype in listargs:
                status, unused = _Marshal(msg, argvalue, argtype)

            logging.debug("Sending signal message with id=%08x", msg.msgId)
            status = _ajlib.AJ_DeliverMsg(byref(msg))

            if errormap[status] != 'OK':
                logging.error("DeliverMsg failure: %s", errormap[status])
                return

            return

        if self.name is None:
            self.name = func.__name__

        func.aj_raw = self.raw

        if self.raw:
            decoratedFunc = func
        else:
            decoratedFunc = wrapped_signal
        decoratedFunc.aj_name = self.name
        decoratedFunc.aj_signal = True
        decoratedFunc.aj_interface = self.interface
        decoratedFunc.aj_handler = func
        return decoratedFunc

class propertyGet(object):
    def __init__(self, interface, name):
        self.interface = interface
        self.name = name
    def __call__(self, func):
        """Called one time, immediately after constructor. Return a function object."""
        def wrapped_propertyGet(ajobj):
            """This will run every time the method is called"""
            logging.debug("wrapped_propertyGet()")

            if not ajobj.isProxy:
                return func(ajobj)

            # For a proxy object, get the value from the remote object

            pm = ajobj.interfaces[self.interface].properties[self.name]
            pi = PropertiesInterface

            msg = _AJ_Message()
            msgId = _PRX_MESSAGE_ID(ajobj.index, ajobj.interfaceIndex[pi.name], pi.methods['Get'].index)
            flags = 0
            timeout = 100*10

            logging.debug("AJ_MarshalMethodCall (property get)")
            status = _ajlib.AJ_MarshalMethodCall(byref(ajobj.bus._struct), byref(msg), msgId,
                                                 ajobj.bus.name, ajobj.bus.sessionId, flags, timeout)
            if errormap[status] != 'OK':
                logging.error("MarshalMethodCall failure: %s", errormap[status])
                return

            propId = _PRX_MESSAGE_ID(ajobj.index, ajobj.interfaceIndex[self.interface], pm.index)
            status = _ajlib.AJ_MarshalPropertyArgs(byref(msg), propId)

            logging.debug("Sending message with id=%08x", msg.msgId)
            status = _ajlib.AJ_DeliverMsg(byref(msg))

            if errormap[status] != 'OK':
                logging.error("DeliverMsg failure: %s", errormap[status])
                return None

            returnVal = []
            ajobj.bus.processMessages(replyId=_REPLY_ID(msgId), replyArgs=[('value', 'v')], replyValues=returnVal)

            if returnVal:
                return returnVal[0].value
            else:
                return None

        wrapped_propertyGet.aj_name = self.name
        wrapped_propertyGet.aj_property = "Get"
        wrapped_propertyGet.aj_interface = self.interface
        wrapped_propertyGet.aj_handler = func

        return wrapped_propertyGet

class propertySet(object):
    def __init__(self, interface, name):
        self.interface = interface
        self.name = name
    def __call__(self, func):
        """Called one time, immediately after constructor. Return a function object."""
        def wrapped_propertySet(ajobj, value):
            """This will run every time the method is called"""
            logging.debug("wrapped_propertySet()")

            if not ajobj.isProxy:
                return func(ajobj, value)

            # For a proxy object, set the value on the remote object

            pm = ajobj.interfaces[self.interface].properties[self.name]
            pi = PropertiesInterface

            msg = _AJ_Message()
            msgId = _PRX_MESSAGE_ID(ajobj.index, ajobj.interfaceIndex[pi.name], pi.methods['Set'].index)
            flags = 0
            timeout = 100*10

            logging.debug("AJ_MarshalMethodCall (property set)")
            status = _ajlib.AJ_MarshalMethodCall(byref(ajobj.bus._struct), byref(msg), msgId,
                                                 ajobj.bus.name, ajobj.bus.sessionId, flags, timeout)
            if errormap[status] != 'OK':
                logging.error("MarshalMethodCall failure: %s", errormap[status])
                return

            propId = _PRX_MESSAGE_ID(ajobj.index, ajobj.interfaceIndex[self.interface], pm.index)
            status = _ajlib.AJ_MarshalPropertyArgs(byref(msg), propId)
            status, unused = _Marshal(msg, value, pm.sig)

            logging.debug("Sending message with id=%08x", msg.msgId)
            status = _ajlib.AJ_DeliverMsg(byref(msg))

            if errormap[status] != 'OK':
                logging.error("DeliverMsg failure: %s", errormap[status])
                return None

            returnVal = []
            ajobj.bus.processMessages(replyId=_REPLY_ID(msgId), replyArgs=[], replyValues=returnVal)

        wrapped_propertySet.aj_name = self.name
        wrapped_propertySet.aj_property = "Set"
        wrapped_propertySet.aj_interface = self.interface
        wrapped_propertySet.aj_handler = func

        return wrapped_propertySet

class Object(_wrappedStructure):
    def __init__(self, bus, path, interfaces):
        self.bus = bus
        self.path = path
        self.flags = 0
        self.interfaces = {}
        self.interfaceIndex = {}
        self.isProxy = False
        self.setProperties = {}
        self.getProperties = {}

        # Automatically add the properties interface if any one of the user-defined interfaces
        # has a property member.
        for interface in interfaces:
            if interface.properties:
                logging.debug("Found properties, adding properties interface to %s", self.path)
                interfaces.append(PropertiesInterface)
                break

        for i, interface in enumerate(interfaces):
            # Interfaces may be shared across Objects, can't stash index directly in interface
            self.interfaces[interface.name] = interface
            self.interfaceIndex[interface.name] = i

        self.index = None # Populated at registration time

        self.interfaceData = _list_to_terminated_array(POINTER(c_char_p),
                                                       [_list_to_terminated_array(c_char_p, i.toStringList()) for i in interfaces])
        logging.debug("Interface list:\n%s", '\n'.join([i.toString(indent=4) for i in interfaces]))

        super(Object, self).__init__(_AJ_Object(self.path, self.interfaceData, self.flags))

    def _getMethodIds(self):
        return self._getMessageIds('aj_method')

    def _getSignalIds(self):
        return self._getMessageIds('aj_signal')

    def _getMessageIds(self, aj_attr):
        messageIds = {}
        for name, methodobj in inspect.getmembers(self, inspect.ismethod):
            if hasattr(methodobj, aj_attr):
                logging.debug("Found %s %s", aj_attr, name)

                if (methodobj.aj_interface == "org.freedesktop.DBus.Properties" and
                    methodobj.aj_interface not in self.interfaceIndex):
                    # Not all objects have properties, but they all inherit Object.__Get and Object.__Set.
                    # Ignore the method object if the properties interface is not in use.
                    continue

                interfaceIndex = self.interfaceIndex[methodobj.aj_interface]
                try:
                    member = self.interfaces[methodobj.aj_interface].members[methodobj.aj_name]
                except KeyError:
                    logging.error('Member name "%s" has a member function in the %s object, but no matching entry in the defined interfaces', methodobj.aj_name, self.path)
                    raise

                if self.isProxy:
                    m_id = _PRX_MESSAGE_ID(self.index, interfaceIndex, member.index)
                else:
                    m_id = _APP_MESSAGE_ID(self.index, interfaceIndex, member.index)

                messageIds[m_id] = (self, methodobj.aj_handler, member)

        return messageIds

    def _setupPropertyIds(self):
        for name, methodobj in inspect.getmembers(self, inspect.ismethod):
            if hasattr(methodobj, "aj_property"):
                logging.debug("Found property method %s", name)
                interfaceIndex = self.interfaceIndex[methodobj.aj_interface]
                try:
                    member = self.interfaces[methodobj.aj_interface].members[methodobj.aj_name]
                except KeyError:
                    logging.error('Member name "%s" has a member function in the %s object, but no matching entry in the defined interfaces', methodobj.aj_name, self.path)
                    raise

                if methodobj.aj_property == "Get":
                    properties = self.getProperties
                else:
                    properties = self.setProperties
                properties[_APP_MESSAGE_ID(self.index, interfaceIndex, member.index)] = (methodobj.aj_handler, member)

    @method(interface='org.freedesktop.DBus.Properties', name="Get", raw=True)
    def __Get(self, msg):
        # Send to AJ lib for further processing.
        # If permissions are ok, _cPropGetCb will be called. That function
        # will handle calling higher-level property getter.
        context = random.randint(0, 0xffffffff)
        while context in propContext:
            context = random.randint(0, 0xffffffff)
        propContext[context] = self
        status = _ajlib.AJ_BusPropGet(byref(msg), _cPropGetCb, c_void_p(context))
        del propContext[context]

    @method(interface='org.freedesktop.DBus.Properties', name="Set", raw=True)
    def __Set(self, msg):
        # Send to AJ lib for further processing.
        # If permissions are ok, _cPropSetCb will be called. That function
        # will handle calling higher-level property setter.
        context = random.randint(0, 0xffffffff)
        while context in propContext:
            context = random.randint(0,sys.maxint)
        propContext[context] = self
        status = _ajlib.AJ_BusPropSet(byref(msg), _cPropSetCb, c_void_p(context))
        del propContext[context]

    @method(interface='org.freedesktop.DBus.Properties', name="GetAll", raw=True)
    def __GetAll(self, interface_name):
        # Does anyone care?
        pass

def aj_debug(level):
    if type(level) in types.StringTypes:
        level = level.lower()
    level = {'off': 0, 'error': 1, 'warn': 2, 'info': 3}.get(level, level)

    aj_dbglevel = c_int.in_dll(_ajlib, "AJ_DbgLevel")
    aj_dbglevel.value = level

# Let ctrl-c work
sig.signal(sig.SIGINT, sig.SIG_DFL)
if (sys.platform == "win32"):
    _ajlib = CDLL("../ajtcl.dll")
else:
    _ajlib = CDLL("../libajtcl.so")
_setup_prototypes(_ajlib)
errormap = _gen_errormap()
msgmap = _gen_msgmap()

aj_debug('off')
#logging.basicConfig(level=logging.DEBUG)
