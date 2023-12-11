project(
    'libdinitctl',
    ['c', 'cpp'],
    version: '0.1',
    default_options: [
        'c_std=c99',
        'cpp_std=c++17',
        'warning_level=3',
        'buildtype=debugoptimized',
    ]
)

pfx = get_option('prefix')
datadir = get_option('datadir')

install_headers('include/libdinitctl.h')

cdata = configuration_data()
cdata.set_quoted('DINIT_CONTROL_SOCKET', get_option('system-control-socket'))

configure_file(output: 'config.h', configuration: cdata)

dbus = dependency('dbus-1', required: get_option('dbus'))
have_dbus = not get_option('dbus').disabled() and dbus.found()

inc = include_directories('include', 'src')

lib = library(
    'dinitctl',
    ['src/libdinitctl.c'],
    include_directories: inc,
    install: true,
    version: meson.project_version(),
    gnu_symbol_visibility: 'hidden',
)

if have_dbus
    dbus_policy_dir = pfx / datadir / 'dbus-1/system.d'
    dbus_system_srv_dir = dbus.get_pkgconfig_variable(
        'system_bus_services_dir',
        define_variable: ['datadir', pfx / datadir]
    )
    dbus_session_srv_dir = dbus.get_pkgconfig_variable(
        'session_bus_services_dir',
        define_variable: ['datadir', pfx / datadir]
    )

    executable(
        'dinit-dbus',
        'src/dinit-dbus.cc',
        install: true,
        include_directories: inc,
        dependencies: [dbus],
        link_with: [lib],
    )

    install_data(
        'data/org.chimera.dinit.service',
        install_dir: dbus_session_srv_dir,
        install_mode: 'rw-r--r--'
    )

    install_data(
        'data/org.chimera.dinit.service',
        install_dir: dbus_system_srv_dir,
        install_mode: 'rw-r--r--'
    )

    install_data(
        'data/org.chimera.dinit.conf',
        install_dir: dbus_policy_dir,
        install_mode: 'rw-r--r--'
    )
endif
