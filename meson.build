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

cdata = configuration_data()
cdata.set_quoted('DINIT_CONTROL_SOCKET', get_option('system-control-socket'))

configure_file(output: 'config.h', configuration: cdata)

inc = include_directories('include', 'src')
src = files('src/libdinitctl.c')

if meson.is_subproject()
    lib = static_library(
        'dinitctl',
        src,
        include_directories: inc,
    )

    dep = declare_dependency(link_with: lib, include_directories: 'include')
    meson.override_dependency('libdinitctl', dep)
else
    lib = library(
        'dinitctl',
        src,
        include_directories: inc,
        install: true,
        version: meson.project_version(),
        gnu_symbol_visibility: 'hidden',
    )

    install_headers('include/libdinitctl.h')

    pc = import('pkgconfig')
    pc.generate(
        lib,
        name: 'libdinitctl',
        description: 'C interface for the dinit control socket',
    )
endif
