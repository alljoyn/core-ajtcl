import os
import platform

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
target_options = [ t.split('.', 1)[1] for t in os.listdir('.') if t.startswith('SConscript.') and not t.endswith('~') ]
vars = Variables()
vars.Add(BoolVariable('V',              'Build verbosity',             False))
vars.Add(EnumVariable('TARG',           'Target platform variant',     os.environ.get('AJ_TARG', default_target), allowed_values = target_options))
vars.Add(EnumVariable('VARIANT',        'Build variant',               os.environ.get('AJ_VARIANT', 'debug'),     allowed_values = ('debug', 'release')))
vars.Add(EnumVariable('WS',             'Whitespace Policy Checker',   os.environ.get('AJ_WS', 'check'),          allowed_values = ('check', 'detail', 'fix', 'off')))
vars.Add(EnumVariable('DEBUG_RESTRICT', 'Set compiled in debug level', os.environ.get('AJ_DEBUG_RESTRICT'),       allowed_values = debug_restrict_options))
vars.Add('CC',  'C Compiler override')
vars.Add('CXX', 'C++ Compiler override')

#######################################################
# Initialize our build environment
#######################################################
env = Environment(variables = vars)
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
# Compilation defines
#######################################################
if env.has_key('DEBUG_RESTRICT'):
    env.Append(CPPDEFINES = { 'AJ_DEBUG_RESTRICT' : env['DEBUG_RESTRICT'] })
if env['VARIANT'] == 'release':
    env.Append(CPPDEFINES = [ 'NDEBUG' ])

#######################################################
# Include path
#######################################################
env.Append(CPPPATH = [ '#dist/include' ])

#######################################################
# Process commandline defines
#######################################################
env.Append(CPPDEFINES = [ v for k, v in ARGLIST if k.lower() == 'define' ])

#######################################################
# Whitespace checker
#######################################################
# Set the location of the uncrustify config file
import sys
sys.path.append(os.getcwd() + '/tools')
import whitespace

def wsbuild(target, source, env):
    return whitespace.main([ env['WS'], os.getcwd() + '/tools/ajuncrustify.cfg' ])

if env['WS'] != 'off':
    env.Command('#ws_ajtcl', '#dist', Action(wsbuild, '$WSCOMSTR'))

#######################################################
# Install header files
#######################################################
env.Install('#dist/include/ajtcl', env.Glob('inc/*.h'))
env.Install('#dist/include/ajtcl', env.Glob('src/target/$TARG/aj_target.h'))

#######################################################
# Build the various parts and setup target specific options
#######################################################
env['build'] = True
env['build_shared'] = False
env['build_unit_tests'] = True

Export('env')
env.SConscript('SConscript.$TARG')
if env['build']:
    env.SConscript('src/SConscript',       variant_dir='#build/$VARIANT',           duplicate = 0)
    env.SConscript('samples/SConscript',   variant_dir='#build/$VARIANT/samples',   duplicate = 0)
    env.SConscript('test/SConscript',      variant_dir='#build/$VARIANT/test',      duplicate = 0)
    env.SConscript('unit_test/SConscript', variant_dir='#build/$VARIANT/unit_test', duplicate = 0)
