import os
import platform
import re

#######################################################
# Custom Configure functions
#######################################################
def CheckCommand(context, cmd):
    context.Message('Checking for %s command...' % cmd)
    r = WhereIs(cmd)
    context.Result(r is not None)
    return r

def CheckAJLib(context, ajlib, ajheader, sconsvarname, ajdistpath):
    prog = "#include <%s>\nint main(void) { return 0; }" % ajheader
    context.Message('Checking for AllJoyn library %s...' % ajlib)

    prevLIBS = context.env['LIBS']
    prevLIBPATH = context.env.get('LIBPATH', [])
    prevCPPPATH = context.env.get('CPPPATH', [])

    # Check if library is in standard system locations
    context.env.Append(LIBS = ajlib)
    defpath = ''  # default path is a system directory
    if not context.TryLink(prog, '.c'):
        # Check if library is in project default location
        context.env.Append(LIBPATH = ajdistpath + '/lib', CPPPATH = ajdistpath + '/include')
        if context.TryLink(prog, '.c'):
            defpath = ajdistpath  # default path is the dist directory
        # Remove project default location from LIBPATH and CPPPATH
        context.env.Replace(LIBPATH = prevLIBPATH, CPPPATH = prevCPPPATH)

    vars = Variables()
    vars.Add(PathVariable(sconsvarname,
                          'Path to %s dist directory' % ajlib,
                          os.environ.get('AJ_%s' % sconsvarname, defpath),
                          lambda k, v, e : v == '' or PathVariable.PathIsDir(k, v, e)))
    vars.Update(context.env)
    Help(vars.GenerateHelpText(context.env))

    # Get the actual library path to use ('' == system path, may be same as ajdistpath)
    libpath = env.get(sconsvarname, '')
    if libpath is not '':
        libpath = str(context.env.Dir(libpath))
        # Add the user specified (or ajdistpath) to LIBPATH and CPPPATH
        context.env.Append(LIBPATH = libpath + '/lib', CPPPATH = libpath + '/include')

    # The real test for the library
    r = context.TryLink(prog, '.c')
    if not r:
        context.env.Replace(LIBS = prevLIBS, LIBPATH = prevLIBPATH, CPPPATH = prevCPPPATH)
    context.Result(r)
    return r

#######################################################
# Default target platform
#######################################################
if platform.system() == 'Linux':
    default_target = 'linux'
elif platform.system() == 'Windows':
    default_target = 'win32'
elif platform.system() == 'Darwin':
    default_target = 'darwin'

#######################################################
# Build variables
#######################################################
debug_restrict_options = (
    '0', 'AJ_DEBUG_OFF',
    '1', 'AJ_DEBUG_ERROR',
    '2', 'AJ_DEBUG_WARN',
    '3', 'AJ_DEBUG_INFO',
    '4', 'AJ_DEBUG_DUMP',
    '5', 'AJ_DEBUG_ALL'
)
target_options = [ t.split('.')[-1] for t in os.listdir('.') if re.match('^SConscript\.target\.[-_0-9A-Za-z]+$', t) ]

vars = Variables()
vars.Add(BoolVariable('V',              'Build verbosity',             False))
vars.Add(EnumVariable('TARG',           'Target platform variant',     os.environ.get('AJ_TARG', default_target), allowed_values = target_options))
vars.Add(EnumVariable('VARIANT',        'Build variant',               os.environ.get('AJ_VARIANT', 'debug'),     allowed_values = ('debug', 'release')))
vars.Add(EnumVariable('DEBUG_RESTRICT', 'Set compiled in debug level', os.environ.get('AJ_DEBUG_RESTRICT'),       allowed_values = debug_restrict_options))
vars.Add('CC',  'C Compiler override')
vars.Add('CXX', 'C++ Compiler override')
vars.Add(EnumVariable('NDEBUG', 'Override NDEBUG default for release variant', 'defined', allowed_values=('defined', 'undefined')))

if platform.system() != 'Windows':
    env = Environment(variables = vars)
else:
    if platform.machine() != 'AMD64':
        target_arch = 'x86'
    else:
        environment_force32 = os.environ.get('AJ_FORCE32', False)
        vars.Add(BoolVariable('FORCE32', 'Force building 32 bit on 64 bit architecture', environment_force32))

        if environment_force32:
            default_force32 = 'true'
        else:
            default_force32 = 'false'

        force32 = ARGUMENTS.get('FORCE32', default_force32)
        force32 = force32.lower()

        if force32 == 'true' or force32 == 'yes' or force32 == '1':
            target_arch = 'x86'
        else:
            target_arch = 'x86_64'

    # Target CPU architecture must be specified here for Windows - otherwise platform.machine() is always used as the target!
    env = Environment(variables = vars, TARGET_ARCH=target_arch)

Export('env')
Help(vars.GenerateHelpText(env))

#######################################################
# Setup non-verbose output
#######################################################
if not env['V']:
    env.Replace( CCCOMSTR =     '\t[CC]      $SOURCE',
                 SHCCCOMSTR =   '\t[CC-SH]   $SOURCE',
                 CXXCOMSTR =    '\t[CXX]     $SOURCE',
                 SHCXXCOMSTR =  '\t[CXX-SH]  $SOURCE',
                 LINKCOMSTR =   '\t[LINK]    $TARGET',
                 SHLINKCOMSTR = '\t[LINK-SH] $TARGET',
                 JAVACCOMSTR =  '\t[JAVAC]   $SOURCE',
                 JARCOMSTR =    '\t[JAR]     $TARGET',
                 ARCOMSTR =     '\t[AR]      $TARGET',
                 ASCOMSTR =     '\t[AS]      $TARGET',
                 RANLIBCOMSTR = '\t[RANLIB]  $TARGET',
                 INSTALLSTR =   '\t[INSTALL] $TARGET',
                 WSCOMSTR =     '\t[WS]      $WS' )

#######################################################
# Load target setup
#######################################################
env['build'] = True
env['build_shared'] = False
env['build_unit_tests'] = True
env['connectivity_options'] = [ 'tcp' ]

env.SConscript('SConscript.target.$TARG')

vars = Variables()
vars.Add('CONNECTIVITY', 'Connectivity mechanism to connect to a routing node (any of ' + ', '.join(env['connectivity_options']) + ')', os.environ.get('AJ_CONNECTIVITY', ' '.join(env['connectivity_options'])))
vars.Update(env)
Help(vars.GenerateHelpText(env))
env['connectivity'] = [ opt.upper() for opt in env['connectivity_options'] if opt in env['CONNECTIVITY'].lower() ]

if len(env['connectivity']) == 0 and not GetOption('help'):
    print '*** Must enable at least one of %s' % ', '.join(env['connectivity_options'])
    Exit(1)

#######################################################
# Build Configuration
#######################################################
config = Configure(env, custom_tests = { 'CheckCommand' : CheckCommand,
                                         'CheckAJLib' : CheckAJLib })
found_ws = config.CheckCommand('uncrustify')
env = config.Finish()

#######################################################
# Compilation defines
#######################################################
if env.has_key('DEBUG_RESTRICT'):
    env.Append(CPPDEFINES = { 'AJ_DEBUG_RESTRICT' : env['DEBUG_RESTRICT'] })
if env['VARIANT'] == 'release' and env['NDEBUG'] == 'defined':
    env.Append(CPPDEFINES = [ 'NDEBUG' ])

env.Append(CPPDEFINES = [ 'AJ_' + conn for conn in env['connectivity'] ])

#######################################################
# Include path
#######################################################
env.Append(CPPPATH = [ '#dist/include' ])

#######################################################
# Process commandline defines
#######################################################
env.Append(CPPDEFINES = [ v for k, v in ARGLIST if k.lower() == 'define' ])

#######################################################
# Install header files
#######################################################
env.Install('#dist/include/ajtcl', env.Glob('inc/*.h'))
env.Install('#dist/include/ajtcl', env.Glob('src/target/$TARG/aj_target.h'))
# Need to force a dpendency here because SCons can't follow nested
# #include dependencies otherwise
env.Depends('#build/$VARIANT', '#dist/include')

# Install service headers
env.Install('#dist/include/ajtcl/services', env.Glob('services/common/inc/*.h'))
env.Install('#dist/include/ajtcl/services', env.Glob('services/config/inc/*.h'))

#######################################################
# Build the various parts
#######################################################
if env['build']:
    env.SConscript('src/SConscript',       variant_dir='#build/$VARIANT/src',       duplicate = 0)
    env.SConscript('samples/SConscript',   variant_dir='#build/$VARIANT/samples',   duplicate = 0)
    env.SConscript('test/SConscript',      variant_dir='#build/$VARIANT/test',      duplicate = 0)
    env.SConscript('unit_test/SConscript', variant_dir='#build/$VARIANT/unit_test', duplicate = 0)

    # Build ConfigService
    env.SConscript('services/common/src/SConscript.config', variant_dir='#build/$VARIANT/services/common/config/src', duplicate = 0)
    env.SConscript('services/config/src/SConscript',        variant_dir='#build/$VARIANT/services/config/src',        duplicate = 0)
    env.SConscript('services/config/samples/SConscript',    variant_dir='#build/$VARIANT/services/config/samples',    duplicate = 0)

#######################################################
# Run the whitespace checker
#######################################################
# Set the location of the uncrustify config file
if found_ws:
    import sys
    sys.path.append(os.getcwd() + '/tools')
    import whitespace

    def wsbuild(target, source, env):
        return whitespace.main([ env['WS'], os.getcwd() + '/tools/ajuncrustify.cfg' ])

    vars = Variables()
    vars.Add(EnumVariable('WS', 'Whitespace Policy Checker', os.environ.get('AJ_WS', 'off'), allowed_values = ('check', 'detail', 'fix', 'off')))

    vars.Update(config.env)
    Help(vars.GenerateHelpText(config.env))

    if env.get('WS', 'off') != 'off':
        env.Command('#ws_ajtcl', '#dist', Action(wsbuild, '$WSCOMSTR'))
