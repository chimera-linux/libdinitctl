project(
    'libdinitctl',
    ['c'],
    version: '0.1',
    default_options: [
        'c_std=c99',
        'warning_level=3',
        'buildtype=debugoptimized',
    ]
)

install_headers('include/libdinitctl.h')

cdata = configuration_data()
cdata.set_quoted('DINIT_CONTROL_SOCKET', get_option('system-control-socket'))

configure_file(output: 'config.h', configuration: cdata)

inc = include_directories('include', 'src')

lib = library(
    'dinitctl',
    ['src/libdinitctl.c'],
    include_directories: inc,
    install: true,
    version: meson.project_version(),
    gnu_symbol_visibility: 'hidden',
)
