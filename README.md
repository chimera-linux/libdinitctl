# libdinitctl

This is a pure-C API to the dinitctl socket interface of the dinit service
manager (https://github.com/davmac314/dinit). It's designed to map closely
to the protocol, while offering a high-level API that can easily integrate
into different event loops and is bindable.

Minimum dinit version: 92cb58eedaf930fed60d17b6247c1f2155c78ec8 (v5 protocol)

This project used to provide a D-Bus interface written in C++; this is no
longer provided here, but rather separated into its own project:

https://github.com/chimera-linux/dinit-dbus

Both projects are developed together, with the D-Bus interface layering on
top of the library and staying matched to it.

## Building

You can build the project with Meson. The only dependencies is a C99 compiler,
and a system capable of running dinit.
