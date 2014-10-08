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

import AJ
import time

# Define an interface object.
# AJ.Interface(interfacename, [list of members])
testInterface = AJ.Interface('org.alljoyn.basic.test',
                             # AJ.MethodMember(name, inArgs=[list of (argname, signature)],
                             #                       outArgs=[list of (argname, signature)])
                             [AJ.MethodMember(name='cat',
                                              inArgs=[('inStr1', 's'), ('inStr2', 's')],
                                              outArgs=[('outStr', 's')]),
                              AJ.MethodMember(name='catarray',
                                              inArgs=[('in', 'as')],
                                              outArgs=[('outStr', 's')]),
                              AJ.MethodMember(name='echob',
                                              inArgs=[('in', 'b')],
                                              outArgs=[('out', 'b')]),
                              AJ.MethodMember(name='echod',
                                              inArgs=[('in', 'd')],
                                              outArgs=[('out', 'd')]),
                              AJ.MethodMember(name='echog',
                                              inArgs=[('in', 'g')],
                                              outArgs=[('out', 'g')]),
                              AJ.MethodMember(name='echoi',
                                              inArgs=[('in', 'i')],
                                              outArgs=[('out', 'i')]),
                              AJ.MethodMember(name='echon',
                                              inArgs=[('in', 'n')],
                                              outArgs=[('out', 'n')]),
                              AJ.MethodMember(name='echoo',
                                              inArgs=[('in', 'o')],
                                              outArgs=[('out', 'o')]),
                              AJ.MethodMember(name='echoq',
                                              inArgs=[('in', 'q')],
                                              outArgs=[('out', 'q')]),
                              AJ.MethodMember(name='echos',
                                              inArgs=[('in', 's')],
                                              outArgs=[('out', 's')]),
                              AJ.MethodMember(name='echot',
                                              inArgs=[('in', 't')],
                                              outArgs=[('out', 't')]),
                              AJ.MethodMember(name='echou',
                                              inArgs=[('in', 'u')],
                                              outArgs=[('out', 'u')]),
                              AJ.MethodMember(name='echox',
                                              inArgs=[('in', 'x')],
                                              outArgs=[('out', 'x')]),
                              AJ.MethodMember(name='echoy',
                                              inArgs=[('in', 'y')],
                                              outArgs=[('out', 'y')]),
                              AJ.MethodMember(name='echoall',
                                              inArgs=[('in', '(bdginoqstuxy)')],
                                              outArgs=[('out', '(bdginoqstuxy)')]),
                              AJ.MethodMember(name='addstruct',
                                              inArgs=[('in', '(xin)')],
                                              outArgs=[('out', 'x')]),
                              AJ.MethodMember(name='swapdict',
                                              inArgs=[('in', 'a{ss}')],
                                              outArgs=[('out', 'a{ss}')]),
                              AJ.MethodMember(name='addarray',
                                              inArgs=[('in', 'ai')],
                                              outArgs=[('out', 'i')]),
                              AJ.MethodMember(name='dictus',
                                              inArgs=[('in', 'a{us}')],
                                              outArgs=[('out', 's')]),
                              AJ.MethodMember(name='nestedarray',
                                              inArgs=[('in', '(iai)')],
                                              outArgs=[('out', 's')]),
                              AJ.MethodMember(name='nestedstruct',
                                              inArgs=[('in', '(i(i(i(i))))')],
                                              outArgs=[('out', 's')]),
                              AJ.MethodMember(name='variant',
                                              inArgs=[('in', 'v')],
                                              outArgs=[('out', 'v')]),
                              # AJ.SignalMember(name, args=[list of (argname, signature)])
                              AJ.SignalMember(name='strsignal',
                                              args=[('value', 's')]),
                              AJ.MethodMember(name='noin',
                                              outArgs=[('out', 'b')]),
                              AJ.MethodMember(name='noout',
                                              inArgs=[('in', 'b')]),
                              AJ.MethodMember(name='noarg'),
                              # AJ.PropertyMember(name, signature, rights=r/w/rw)
                              AJ.PropertyMember(name='prop',
                                                sig='i',
                                                rights='rw'),
                              AJ.PropertyMember(name='strProp',
                                                sig='s',
                                                rights='rw'),
                              AJ.MethodMember(name='triggerglobalsignal',
                                              outArgs=[('out', 'b')]),
                              AJ.SignalMember(name='globalsignal',
                                              args=[('time', 's')]),
                              ])

class sample(AJ.Object):
    def __init__(self, bus, path):
        # This call to the superclass constructor (AJ.__init__) is needed to configure
        # the superclass to intercept method calls.
        # __init__(bus object, object path, [list of AJ.Interface objects this object uses])
        super(sample, self).__init__(bus, path, [testInterface])
        self._prop = 0
        self._strProp = "<empty>"

    # Lines starting with '@' before a method definition are decorators. These
    # allow method calls to be intercepted by the AJ.Object superclass

    # Each readable property needs a method decorated with AJ.propertyGet.
    # This method returns the property value to be sent when a property value
    # is read from this object using AllJoyn.
    #
    # args: interface = name of an AJ.Interface object defining the property
    #       name = name of property
    @AJ.propertyGet(interface='org.alljoyn.basic.test',
                    name='prop')
    def getProp(self):
        # Note that the member variable read is self._prop, not self.prop
        return self._prop

    # Each writeable property needs a method decorated with AJ.propertySet.
    # This method sets the property value in the to be sent when a property value
    # is read from this object using AllJoyn.
    @AJ.propertySet(interface='org.alljoyn.basic.test',
                    name='prop')
    def setProp(self, value):
        # Note that the member variable assigned is self._prop, not self.prop
        self._prop = value

    # This is purely a Python hook, so assigments to or reads from object.prop in python code
    # trigger the getProp/setProp method calls.
    prop = property(getProp, setProp)

    @AJ.propertyGet(interface='org.alljoyn.basic.test',
                    name='strProp')
    def getStrProp(self):
        return self._strProp

    @AJ.propertySet(interface='org.alljoyn.basic.test',
                    name='strProp')
    def setStrProp(self, value):
        self._strProp = value

    strProp = property(getStrProp, setStrProp)

    # Each method intended to be called via AllJoyn must have an AJ.method decorator
    # AJ.method(name, interface)
    # If the 'name' arg is omitted, it defaults to the name of the function - in this case,
    # the name defaults to 'cat'.
    @AJ.method(interface='org.alljoyn.basic.test')
    def cat(self, inStr1, inStr2):
        # The body of an AJ.method decorated function will only execute for local objects,
        # not proxy objects. If the code is only intended for use with a proxy object,
        # the body of the function is never executed and may simply be the keyword 'pass'.
        # For proxy objects, AJ.Object intercepts the call and provides the AllJoyn method
        # call return value
        return [inStr1 + inStr2]

    @AJ.method(interface='org.alljoyn.basic.test')
    def catarray(self, stringlist):
        return [''.join(stringlist)]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echob(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echod(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echog(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echoi(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echon(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echoo(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echoq(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echos(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echot(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echou(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echox(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echoy(self, v):
        return [v]

    @AJ.method(interface='org.alljoyn.basic.test')
    def echoall(self, a):
        return [a]

    @AJ.method(interface='org.alljoyn.basic.test')
    def addstruct(self, ints):
        return [sum(ints)]

    @AJ.method(interface='org.alljoyn.basic.test')
    def swapdict(self, d):
        swapped = {}
        for key, value in d.iteritems():
            swapped[value] = key
        return [swapped]

    @AJ.method(interface='org.alljoyn.basic.test')
    def addarray(self, ints):
        if ints:
            return [sum(ints)]
        else:
            return [0]

    @AJ.method(interface='org.alljoyn.basic.test')
    def dictus(self, adict):
        return repr(adict)

    @AJ.method(interface='org.alljoyn.basic.test')
    def nestedarray(self, arg):
        return repr(arg)

    @AJ.method(interface='org.alljoyn.basic.test')
    def nestedstruct(self, arg):
        return repr(arg)

    @AJ.method(interface='org.alljoyn.basic.test')
    def variant(self, arg):
        return arg

    # Each signal must have an AJ.signal decorator
    # AJ.signal(name, interface)
    # If the 'name' arg is omitted, it defaults to the name of the function - in this case,
    # the name defaults to 'strsignal'.
    @AJ.signal(interface='org.alljoyn.basic.test')
    def strsignal(self, arg):
        # This code is executed when a signal is received
        print arg

    @AJ.method(interface='org.alljoyn.basic.test')
    def noin(self):
        return True

    @AJ.method(interface='org.alljoyn.basic.test')
    def noout(self, arg):
        return []

    @AJ.method(interface='org.alljoyn.basic.test')
    def noarg(self):
        return []

    @AJ.method(interface='org.alljoyn.basic.test')
    def triggerglobalsignal(self):
        # When this method is called, send a sessionless signal
        self.globalsignal(time.asctime())
        return [True]

    @AJ.signal(interface='org.alljoyn.basic.test')
    def globalsignal(self, t):
        print t
