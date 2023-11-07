# libdinitctl

This is a pure-C API to the dinitctl socket interface of the dinit service
manager (https://github.com/davmac314/dinit). It's designed to map closely
to the protocol, while offering a high-level API that can easily integrate
into different event loops and is bindable.

Currently it's incomplete.

## Building

You can build the project with Meson. The only dependency is a C99 compiler
and a system capable of running dinit.
