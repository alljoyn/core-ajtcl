# Copyright (c) 2012-2013, AllSeen Alliance. All rights reserved.
#
#    Permission to use, copy, modify, and/or distribute this software for any
#    purpose with or without fee is hereby granted, provided that the above
#    copyright notice and this permission notice appear in all copies.
#
#    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import os

env = SConscript(['conf/SConscript'])

# Services should be built or not?
vars = Variables()
vars.Add('SERVICES', 'AllJoyn Thin services libraries to buid (comma separated list, about always included): about,config,controlpanel,notification,onboarding,sample_apps,services_common', 'about')
vars.Update(env)
Help(vars.GenerateHelpText(env))

# Services configurations. Having as a base current 
# Add about service for the moment as hardcoded
if not 'about' in env['SERVICES']:
    env['SERVICES'] += ',about'

services = set([ s.strip()
                 for s in env['SERVICES'].split(',')
                 if s.strip() == 'about' or os.path.exists('../../services/base_tcl/%s/SConscript' % s.strip())])

env['services'] = services

# Always build AllJoyn Thin Client
env.SConscript(['SConscript'])

if services.intersection(['config', 'controlpanel', 'notification', 'onboarding', 'audio', 'about']):
    if services.intersection(['about']):
        env['_ALLJOYN_ABOUT_'] = True

    env['APP_COMMON_DIR'] = env.Dir('../../services/base_tcl/sample_apps')

    if services.intersection(['config', 'onboarding']):
        # onboarding also depends on config
        env.SConscript(['../../services/base_tcl/config/SConscript'])

        if 'onboarding' in services:
            env.SConscript(['../../services/base_tcl/onboarding/SConscript'])

    if services.intersection(['controlpanel', 'notification']):
        # controlpanel also depends on notification
        env.SConscript(['../../services/base_tcl/notification/SConscript'])

        if 'controlpanel' in services:
            env.SConscript(['../../services/base_tcl/controlpanel/SConscript'])


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
