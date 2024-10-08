# libdinitctl

This is a pure-C API to the dinitctl socket interface of the dinit service
manager (https://github.com/davmac314/dinit). It's designed to map closely
to the protocol, while offering a high-level API that can easily integrate
into different event loops and is bindable.

Needs dinit 0.18.0 or newer (protocol v4).

## Building

You can build the project with Meson. The only dependencies are a C99 compiler,
a C++17 compiler, a system capable of running dinit, and optionally the D-Bus
reference library (`dbus-1`).

## D-Bus interface

Optionally, this project also provides a D-Bus API. It is exposed by a daemon
called `dinit-dbus`.

The daemon is meant to run as a dinit service. Such service should specify:

```
ready-notification = pipevar:DINIT_DBUS_READY_FD
options = pass-cs-fd
```

When executed, the service will use the available file descriptor for control
and will signal readiness at an appropriate time.

You can also specify the file descriptor manually (`-f FD`) or specify the
socket path (`-S /path/to/socket`).

### API

The API generally mirrors the C API. One difference is that since the
D-Bus API uses global objects available to any caller, all actions
work by service name instead of using handles. Handles are instead
set up internally and temporarily for the lifetime of an event.

This also means every method that takes a service name may raise the
same errors service loading would raise in the C API.

The following interfaces are available:

* `org.chimera.dinit.Manager`
* `org.chimera.dinit.Activator`

The `Manager` interface is implemented by the object `/org/chimera/dinit`,
which is present on the bus from the start.

It implements the following methods:

* `UnloadService(in s name, in b reload)`
* `StartService(in s name, in b pin, out u eventid)`
* `StopService(in s name, in b pin, in b restart, in b gentle, out u eventid)`
* `WakeService(in s name, in b pin, out u eventid)`
* `ReleaseService(in s name, in b pin, out u eventid)`
* `UnpinService(in s name)`
* `AddRemoveServiceDependency(in s from_name, in s to_name, in s type, in b remove, in b enable)`
* `GetServiceDirectory(in s name, out s dir)`
* `GetServiceLog(in s name, in b clear, out s log)`
* `GetServiceStatus(in s name, out (ssssa{sb}uii) status)`
* `SetServiceTrigger(in s name, in b trigger)`
* `SignalService(in s name, in s signal)`
* `ListServices(out a(sssssa{sb}ui) list)`
* `SetEnvironment(in as env_vars)`
* `GetAllEnvironment(out as list)`
* `Shutdown(in s type)`
* `QueryServiceDirs(out as list)`

Notably, the `SetEnvironment` differs from `dinitctl_setenv` in that it can
take multiple environment variables (it will chain multiple protocol messages)
and that it requires the input strings to always be in the format `NAME=VALUE`
to set the variables, with just `NAME` unsetting them (because the invocation
happens from a different process than the caller's). A mix of setting and
unsetting is permitted.
The first failed (un)setenv will raise the D-Bus error, i.e. everything up
until the failed one will be (un)set.

And the following signals:

* `ServiceEvent(u eventid, s event, (ssssa{sb}uii) status)`
* `EnvironmentEvent(s env, b overridden)`

The `Activator` interface provides two signals:

* `ActivationRequest(s name)`
* `ActivationFailure(s name, s error, s message)`

The daemon will subscribe to the `ActivationRequest` signal on
`/org/freedesktop/DBus` with destination `org.chimera.dinit`, interface
`org.chimera.dinit.Activator`. The bus controller may then emit it, which will
make `dinit-dbus` activate the service. Its sole argument is the service name.

In case of activation failure, the `ActivationFailure` signal will be emitted
on the `/org/chimera/dinit` object. It takes the service name, the error name,
and the error message. The D-Bus controller may subscribe to it and emit the
appropriate error as needed.

The `dinitctl_error` enum is mapped to D-Bus errors. The following errors
are provided:

* `org.chimera.dinit.Error.Error`
* `org.chimera.dinit.Error.ShuttingDown`
* `org.chimera.dinit.Error.ServiceMissing`
* `org.chimera.dinit.Error.ServiceDesc`
* `org.chimera.dinit.Error.ServiceLoad`
* `org.chimera.dinit.Error.ServiceNoPid`
* `org.chimera.dinit.Error.ServiceBadSignal`
* `org.chimera.dinit.Error.ServiceSignalFailed`
* `org.chimera.dinit.Error.ServicePinned`
* `org.chimera.dinit.Error.ServiceAlready`
* `org.chimera.dinit.Error.ServiceDependents`

Non-recoverable errors from the C API will result in `dinit-dbus` shutting
down and kicking out any clients.

Other enums translate to strings. Passing an invalid string will result in
the `org.freedesktop.DBus.Error.InvalidArgs` error. In general, conditions
that would raise `EINVAL` in C will also result in that error.

For service state:

* `stopped`
* `starting`
* `started`
* `stopping`

For dependency type:

* `regular`
* `waits_for`
* `milestone`

For stop rason:

* `normal`
* `dep_restart`
* `dep_failed`
* `failed`
* `exec_failed`
* `timeout`
* `terminated`

For execution stage:

* `fds`
* `env`
* `readiness`
* `activation_socket`
* `control_socket`
* `chdir`
* `stdio`
* `cgroup`
* `rlimits`
* `uid_gid`

For service event type:

* `stated`
* `stopped`
* `start_failed`
* `start_canceled`
* `stop_canceled`

For shutdown type:

* `remain`
* `halt`
* `poweroff`
* `reboot`

Service flags are provided as a dictionary with string keys and boolean values.
Currently available keys are:

* `waiting_for_console`
* `has_console`
* `was_start_skipped`
* `is_marked_active`
* `has_pid`

The service status is a struct with the signature `(ssssa{sb}uii)`. The
fields here are:

* service state
* service target state
* service stop reason
* service exec stage
* flags dict
* PID
* exit code
* and exit status

For `ListServices`, the output is an array of structs. This array matches
the the status struct, except it also has an additional member (service name)
at the beginning.

### Usage from command line

You can use something like this:

```
$ dbus-send --dest=org.chimera.dinit --print-reply --type=method_call /org/chimera/dinit org.chimera.dinit.Manager.GetServiceStatus string:dbus
```

and so on. You can also subscribe to signals with `dbus-monitor`.
