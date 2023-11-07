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

library(
    'dinitctl',
    ['src/libdinitctl.c'],
    include_directories: include_directories('include', 'src'),
    install: true,
    version: meson.project_version(),
)
