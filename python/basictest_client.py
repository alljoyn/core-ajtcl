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
import basictest
import logging
import sys

#logging.basicConfig(level=logging.DEBUG)

AJ.Initialize()

bus = AJ.BusAttachment()
# Create an object with object path '/'
s = basictest.sample(bus, "/")

#AJ.PrintXML(s)
# bus.registerObjects([list of bus objects], [list of proxy bus objects])
# Use None if there are no bus or proxy objects in one of the lists. This
# example has only proxy objects and no local bus objects.
bus.registerObjects(None, [s])

# startClient(self, daemonName, timeout, connected, name, port, opts)
status = bus.startClient(None, 1000*60, False, "org.alljoyn.basic.test", 25, None)

# Sessionless signals are not enabled by default
bus.enableSessionlessSignals()

# Make method calls by calling member functions of an object.
print s.cat("Hello ", "World!")
print s.catarray(["Hello ", "to ", "this ", "crazy ", "world"])
print s.echob(True)
print s.echod(3.14159)
print s.echog('g')
print s.echoi(52)
print s.echon(41)
print s.echoo('/path')
print s.echoq(246)
print s.echos('string')
print s.echot(46)
print s.echou(76)
print s.echox(89)
print s.echoy(99)

print s.echoall([True, 3.14159, 'g', 5, 24, '/xyz', 74, 'abc', 25, 75, 123, 1])

print s.addstruct([500, 40, 3])

print s.swapdict({'one': '1', 'two': '2', 'three': '3'})

print s.addarray(range(10))

print s.dictus({123: 'one hundred twenty three', 456: 'four hundred fifty six'})

print s.nestedarray([42, [6,5,4,3,2,1]])

print s.nestedstruct([0,[1,[2,[3]]]])

print s.variant(1)
print s.variant([1,2,3,True])
print s.variant(AJ.Variant(AJ.Variant(AJ.Variant(AJ.Variant(AJ.Variant(1, 'u'))))))

# Send a directed signal to the service's object
s.strsignal("Received directed signal!")

print s.noin()
print s.noout(True)
print s.noarg()

# Get and set properties.
print s.prop
s.prop = 123
print s.prop
s.prop = 456
print s.prop
print s.strProp
s.strProp = "Value is set"
print s.strProp

# Call method that will cause the service to send a sessionless signal
print s.triggerglobalsignal()

# Dummy method call helps to postpone program exit until after the signal
# is received.
print s.noarg()
