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

v = AJ.Variant(None, None)

print "b:", v._inferSignature(True)
print "i:", v._inferSignature(1)
print "x:", v._inferSignature(1L)
print "s:", v._inferSignature('string')
print "d:", v._inferSignature(0.0)
print "None:", v._inferSignature(1j) # Complex number should not map

print "ab:", v._inferSignature((True, False))
print "ai:", v._inferSignature((1, 2))
print "ax:", v._inferSignature((1L, 2L))
print "as:", v._inferSignature(('a', 'b'))
print "ad:", v._inferSignature((1.0, 2.0))
print "None:", v._inferSignature((1j, 2j)) # Complex number should not map

print "(bixsd):", v._inferSignature((True, 1, 1L, 'a', 1.0))
print "None:", v._inferSignature((True, 1, 1L, 'a', 1.0, 1j))

print "a{sb}:", v._inferSignature({'true': True, 'false': False})
print "a{sv}:", v._inferSignature({'true': True, 'false': 0})
print "None:", v._inferSignature({'true': True, 'false': 1j})

print "(ibasa{is}):", v._inferSignature((1, True, ('hello', 'world'), {1: 'one', 2: 'two'}))
print "None:", v._inferSignature((1, True, ('hello', 'world'), {1: 'one', 2: 'two'}, ()))
