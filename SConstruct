# # 
#    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
#    Source Project Contributors and others.
#    
#    All rights reserved. This program and the accompanying materials are
#    made available under the terms of the Apache License, Version 2.0
#    which accompanies this distribution, and is available at
#    http://www.apache.org/licenses/LICENSE-2.0


import os

env = SConscript(['SConscript'])

# Add/remove projects from build
env.SConscript('test/SConscript')
env.SConscript('samples/SConscript')

# Build googletests for VARIANT=debug and for Win/Linux only (not for embedded)
if env['TARG'] == 'win32' or env['TARG'] == 'linux':
    if env['VARIANT'] == 'debug':
        if env.has_key('GTEST_DIR'):
            env.SConscript('unit_test/SConscript')
        else:
            print 'GTEST_DIR is not set, skipping unittest build'