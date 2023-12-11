/*
 * A control interface for dinit on D-Bus.
 *
 * This is basically dinitctl, but implemented as a D-Bus object.
 * It provides an interface that can be used from other applications.
 * It's meant to run as a long-running daemon launched as a dinit
 * service, typically with pass-cs-fd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 q66 <q66@chimera-linux.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <vector>
#include <string>
#include <utility>
#include <new>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <err.h>

#include <dbus/dbus.h>
#include <libdinitctl.h>

#define BUS_NAME "org.chimera.dinit"
#define BUS_IFACE BUS_NAME ".Manager"
#define BUS_SIFACE BUS_NAME ".Service"
#define BUS_OBJ "/org/chimera/dinit"
#define BUS_ERROR_NS BUS_NAME ".Error."
#define BUS_ERROR BUS_ERROR_NS "Failed"

#define ACTIVATOR_IFACE BUS_NAME ".Activator"
#define ACTIVATOR_SIGNAL "Activate"
#define ACTIVATOR_FAILURE "ActivationFailure"
#define ACTIVATOR_ERROR BUS_ERROR_NS ACTIVATOR_FAILURE

static inline bool check_arrbounds(int v, std::size_t tv) {
    return (v >= 0) && (std::size_t(v) < (tv / sizeof(void *)));
}

static inline int str_to_enum(
    char const *str, char const **sarr, std::size_t ssize
) {
    for (std::size_t i = 0; i < (ssize / sizeof(void *)); ++i) {
        if (!sarr[i]) {
            continue;
        }
        if (!std::strcmp(str, sarr[i])) {
            return int(i);
        }
    }
    return -1;
}

static inline char const *enum_to_str(
    int val, char const **sarr, std::size_t ssize, char const *def
) {
    if (!check_arrbounds(val, ssize)) {
        return def;
    }
    return sarr[val] ? sarr[val] : def;
}

static char const *error_str[] = {
    nullptr,
    BUS_ERROR_NS "Error",
    BUS_ERROR_NS "ShuttingDown",
    BUS_ERROR_NS "ServiceMissing",
    BUS_ERROR_NS "ServiceDesc",
    BUS_ERROR_NS "ServiceLoad",
    BUS_ERROR_NS "ServiceNoPid",
    BUS_ERROR_NS "ServiceBadSignal",
    BUS_ERROR_NS "ServiceSignalFailed",
    BUS_ERROR_NS "ServicePinned",
    BUS_ERROR_NS "ServiceAlready",
    BUS_ERROR_NS "ServiceDependents",
};

static char const *service_state_str[] = {
    "stopped",
    "starting",
    "started",
    "stopping",
};

static char const *dependency_type_str[] = {
    "regular",
    nullptr,
    "waits_for",
    "milestone",
};

static char const *service_stop_reason_str[] = {
    "normal",
    "dep_restart",
    "dep_failed",
    "failed",
    "exec_failed",
    "timeout",
    "terminated",
};

static char const *service_exec_stage_str[] = {
    "fds",
    "env",
    "readiness",
    "activation_socket",
    "control_socket",
    "chdir",
    "stdio",
    "cgroup",
    "rlimits",
    "uid_gid",
};

static char const *service_event_str[] = {
    "started",
    "stopped",
    "start_failed",
    "start_canceled",
    "stop_canceled",
};

static char const *shutdown_type_str[] = {
    nullptr,
    "remain",
    "halt",
    "poweroff",
    "reboot",
};

/* utilities */

static void usage(FILE *f) {
    extern char const *__progname;
    std::fprintf(f, "Usage: %s [OPTION]...\n"
"\n"
"Provide a dinit control interface on system or session bus.\n"
"\n"
"If no socket or file descriptor is provided, environment variable\n"
"DINIT_CS_FD is read to get the file descriptor number.\n"
"\n"
"Readiness notification is signaled on DINIT_DBUS_READY_FD\n"
"if set in the environment and if referring to a valid fd.\n"
"\n"
"      -h          Print this message and exit.\n"
"      -a ADDRESS  The bus address to connect to.\n"
"      -f FD       The file descriptor for dinitctl.\n"
"      -S SOCK     The path to dinitctl socket (if no FD).\n"
"      -s          Use the system bus (session bus is default).\n",
        __progname
    );
}

static int get_fd(char const *str) {
    if (!str || !*str) {
        return -1;
    }
    char *end = nullptr;
    unsigned long fd = std::strtoul(str, &end, 10);
    if (fd && end && !*end && (fd <= INT_MAX)) {
        int tfd = (int)fd;
        if (fcntl(tfd, F_GETFD) >= 0) {
            if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
                close(tfd);
                return -1;
            }
            return tfd;
        }
    }
    return -1;
}

/* globals and structures */

static DBusError dbus_err;
static dinitctl *ctl;

struct timer;
struct watch;

static std::vector<pollfd> fds;
static std::vector<timer> timers;
static std::vector<watch> watches;

struct watch {
    pollfd pfd{};
    DBusWatch *watchp;

    watch() = delete;

    watch(watch const &) = delete;
    watch &operator=(watch const &) = delete;

    watch(watch &&v): pfd{v.pfd}, watchp{v.watchp} {
        v.pfd.fd = -1;
        v.watchp = nullptr;
    }

    watch &operator=(watch &&v) {
        pfd = v.pfd;
        watchp = v.watchp;
        v.pfd.fd = -1;
        v.watchp = nullptr;
        return *this;
    }

    watch(DBusWatch *w) {
        pfd.fd = dbus_watch_get_unix_fd(w);
        pfd.revents = pfd.events = 0;

        auto flags = dbus_watch_get_flags(w);
        if (flags & DBUS_WATCH_READABLE) {
            pfd.events |= POLLIN;
        }
        if (flags & DBUS_WATCH_WRITABLE) {
            pfd.events |= POLLOUT;
        }

        watchp = w;
        dbus_watch_set_data(w, this, nullptr);
    }

    ~watch() {
        if (!watchp) {
            return;
        }
        disable();
        dbus_watch_set_data(watchp, nullptr, nullptr);
    }

    static void setup(DBusConnection *conn) {
        auto add_cb = [](DBusWatch *w, void *) -> dbus_bool_t {
            if (!dbus_watch_get_enabled(w)) {
                return true;
            }
            try {
                if (!watches.emplace_back(w).enable()) {
                    watches.pop_back();
                    return false;
                }
            } catch (std::bad_alloc const &) {
                return false;
            }
            return true;
        };
        auto remove_cb = [](DBusWatch *w, void *) {
            for (auto it = watches.begin(); it != watches.end();) {
                if (w == it->watchp) {
                    watches.erase(it);
                    break;
                }
            }
        };
        auto toggle_cb = [](DBusWatch *w, void *) {
            static_cast<watch *>(dbus_watch_get_data(w))->toggle();
        };
        if (!dbus_connection_set_watch_functions(
            conn, add_cb, remove_cb, toggle_cb, nullptr, nullptr
        )) {
            errx(1, "could not set watch functions");
        }
    }

    bool enable() {
        try {
            fds.emplace_back(pfd);
        } catch (std::bad_alloc const &) {
            return false;
        }
        return true;
    }

    void disable() {
        for (auto &pf: fds) {
            if (pf.fd == pfd.fd) {
                pf.fd = -1;
                break;
            }
        }
    }

    bool matches(pollfd const &opfd) const {
        return (pfd.fd == opfd.fd) && (pfd.events == opfd.events);
    }

    void toggle() {
        if (dbus_watch_get_enabled(watchp)) {
            enable();
        } else {
            disable();
        }
    }

    bool handle(pollfd const &pfd) {
        unsigned int hfl = 0;
        if (pfd.revents & POLLIN) {
            hfl |= DBUS_WATCH_READABLE;
        }
        if (pfd.revents & POLLOUT) {
            hfl |= DBUS_WATCH_WRITABLE;
        }
        return dbus_watch_handle(watchp, hfl);
    }
};

struct timer {
    sigevent sev{};
    timer_t tid{};
    DBusTimeout *timeout;

    timer() = delete;

    timer(timer const &) = delete;
    timer &operator=(timer const &) = delete;

    timer(timer &&v): sev{v.sev}, tid{v.tid}, timeout{v.timeout} {
        v.timeout = nullptr;
        v.tid = timer_t{};
    }

    timer &operator=(timer &&v) {
        sev = v.sev;
        tid = v.tid;
        timeout = v.timeout;
        v.timeout = nullptr;
        v.tid = timer_t{};
        return *this;
    }

    timer(DBusTimeout *t, bool &ret) {
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGALRM;
        sev.sigev_value.sival_ptr = this;
        timeout = t;
        dbus_timeout_set_data(t, this, nullptr);

        if (timer_create(CLOCK_MONOTONIC, &sev, &tid) < 0) {
            ret = false;
        }
    }

    ~timer() {
        if (!timeout) {
            return;
        }
        timer_delete(tid);
        dbus_timeout_set_data(timeout, nullptr, nullptr);
    }

    static void setup(DBusConnection *conn) {
        auto add_cb = [](DBusTimeout *t, void *) -> dbus_bool_t {
            bool ret = true;
            if (!dbus_timeout_get_enabled(t)) {
                return ret;
            }
            try {
                timers.emplace_back(t, ret).arm();
            } catch (std::bad_alloc const &) {
                warnx("out of memory");
                return false;
            }
            if (!ret) {
                timers.pop_back();
            }
            return ret;
        };
        auto remove_cb = [](DBusTimeout *t, void *) {
            for (auto it = timers.begin(); it != timers.end();) {
                if (t == it->timeout) {
                    timers.erase(it);
                    break;
                }
            }
        };
        auto toggle_cb = [](DBusTimeout *t, void *) {
            static_cast<timer *>(dbus_timeout_get_data(t))->toggle();
        };
        if (!dbus_connection_set_timeout_functions(
            conn, add_cb, remove_cb, toggle_cb, nullptr, nullptr
        )) {
            errx(1, "could not set timeout functions");
        }
    }

    /* or disarm, with 0 value */
    void arm(int ms) {
        itimerspec tval{};
        /* initial expiration */
        tval.it_value.tv_sec = ms / 1000;
        tval.it_value.tv_nsec = (ms % 1000) * 1000 * 1000;
        /* dbus timeouts need to repeat */
        tval.it_interval = tval.it_value;

        /* arm it */
        if (timer_settime(tid, 0, &tval, nullptr) < 0) {
            /* unreachable */
            err(1, "timer_settime failed");
        }
    }

    void arm() {
        arm(dbus_timeout_get_interval(timeout));
    }

    void disarm() {
        arm(0);
    }

    void toggle() {
        if (dbus_timeout_get_enabled(timeout)) {
            arm();
        } else {
            disarm();
        }
    }

    bool handle() {
        return dbus_timeout_handle(timeout);
    }
};

struct pending_msg {
    DBusConnection *conn;
    DBusMessage *msg;
    dinitctl_service_handle *handle = nullptr;
    dinitctl_service_handle *handle2 = nullptr;
    void *data;
    int type;
    dbus_bool_t reload, pin, gentle, remove, enable, is_signal = FALSE;

    pending_msg() = delete;
    pending_msg(DBusConnection *c, DBusMessage *p):
        conn{c}, msg{dbus_message_ref(p)}
    {}
    pending_msg(pending_msg const &) = delete;
    pending_msg(pending_msg &&v) {
        std::memcpy(this, &v, sizeof(pending_msg));
        std::memset(&v, 0, sizeof(pending_msg));
    }
    ~pending_msg() {
        if (msg) {
            dbus_message_unref(msg);
        }
        drop_handle(handle);
        drop_handle(handle2);
    }

    void drop_handle(dinitctl_service_handle *&h) {
        if (!h) {
            return;
        }
        auto close_cb = [](dinitctl *sctl, void *) {
            dinitctl_close_service_handle_finish(sctl);
        };
        if (dinitctl_close_service_handle_async(ctl, h, close_cb, nullptr) < 0) {
            dinitctl_abort(ctl, EBADMSG);
        }
        h = nullptr;
    }

    pending_msg &operator=(pending_msg const &) = delete;
    pending_msg &operator=(pending_msg &&v) {
        std::memcpy(this, &v, sizeof(pending_msg));
        std::memset(&v, 0, sizeof(pending_msg));
        return *this;
    }
};

static std::vector<pending_msg> pending_msgs;

static pending_msg &add_pending(DBusConnection *conn, DBusMessage *msg) {
    return pending_msgs.emplace_back(conn, msg);
}

static void drop_pending(pending_msg &msg) {
    for (auto it = pending_msgs.begin(); it != pending_msgs.end(); ++it) {
        if (&*it == &msg) {
            pending_msgs.erase(it);
            break;
        }
    }
}

template<typename ...A>
static bool msg_get_args(DBusMessage *msg, A const &...args) {
    if (!dbus_message_get_args(msg, &dbus_err, args..., DBUS_TYPE_INVALID)) {
        dbus_error_free(&dbus_err);
        return false;
    }
    return true;
}

static bool msg_send_error(
    DBusConnection *conn, DBusMessage *msg, char const *err, char const *desc
) {
    if (!err) {
        warn("unknown dinitctl error");
        return false;
    }
    DBusMessage *ret = dbus_message_new_error(msg, err, desc);
    if (!ret || !dbus_connection_send(conn, ret, nullptr)) {
        warnx("dbus_connection_send failed");
        if (ret) {
            dbus_message_unref(ret);
        }
        return false;
    }
    dbus_message_unref(ret);
    return true;
}

static DBusMessage *msg_new_reply(dinitctl *sctl, pending_msg &pend) {
    if (dbus_message_get_no_reply(pend.msg)) {
        drop_pending(pend);
        return nullptr;
    }
    DBusMessage *retm = dbus_message_new_method_return(pend.msg);
    if (!retm) {
        drop_pending(pend);
        warnx("could not build method reply");
        dinitctl_abort(sctl, EBADMSG);
        return nullptr;
    }
    return retm;
}

static bool check_error(dinitctl *sctl, pending_msg &pend, int ret) {
    if (ret < 0) {
        dinitctl_abort(sctl, errno);
        drop_pending(pend);
        return false;
    } else if (ret) {
        if (!msg_send_error(
            pend.conn, pend.msg,
            enum_to_str(ret, error_str, sizeof(error_str), nullptr),
            nullptr
        )) {
            dinitctl_abort(sctl, EBADMSG);
        }
        drop_pending(pend);
        return false;
    }
    return true;
}

static bool send_reply(dinitctl *sctl, pending_msg &pend, DBusMessage *retm) {
    if (!dbus_connection_send(pend.conn, retm, nullptr)) {
        warnx("dbus_connection_send failed");
        dinitctl_abort(sctl, EBADMSG);
        drop_pending(pend);
        return false;
    }
    dbus_message_unref(retm);
    return true;
}

static bool call_load_service(
    pending_msg &pend, DBusConnection *conn,
    char const *service_name, bool find, dinitctl_async_cb cb
) {
    int ret = dinitctl_load_service_async(ctl, service_name, find, cb, &pend);
    if (ret < 0) {
        if (errno == EINVAL) {
            drop_pending(pend);
            return msg_send_error(
                conn, pend.msg, DBUS_ERROR_INVALID_ARGS, nullptr
            );
        }
        warn("dinitctl_load_service_async");
        drop_pending(pend);
        dinitctl_abort(ctl, EBADMSG);
        return false;
    }
    return true;
}

struct manager_unload_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_unload_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        if (dinitctl_unload_service_async(
            ctl, handle, pend.reload, async_cb, &pend
        ) < 0) {
            warn("dinitctl_unload_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t reload;

        if (!msg_get_args(
            msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &reload
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.reload = reload;

        return call_load_service(pend, conn, service_name, true, load_cb);
    }
};

struct manager_start_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_start_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            drop_pending(pend);
            warnx("could not set reply value");
            dinitctl_abort(sctl, EBADMSG);
            return;
        }
        send_reply(sctl, pend, retm);
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_start_service_async(
            ctl, handle, pend.pin, async_cb, &pend
        ) < 0) {
            warn("dinitctl_start_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin;

        if (!msg_get_args(
            msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &pin
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.pin = pin;

        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_stop_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_stop_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            drop_pending(pend);
            warnx("could not set reply value");
            dinitctl_abort(sctl, EBADMSG);
            return;
        }
        send_reply(sctl, pend, retm);
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_stop_service_async(
            ctl, handle, pend.pin, pend.reload, pend.gentle, async_cb, &pend
        ) < 0) {
            warn("dinitctl_stop_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin, restart, gentle;

        if (!msg_get_args(
            msg,
            DBUS_TYPE_STRING, &service_name,
            DBUS_TYPE_BOOLEAN, &pin,
            DBUS_TYPE_BOOLEAN, &restart,
            DBUS_TYPE_BOOLEAN, &gentle
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.pin = pin;
        pend.reload = restart;
        pend.gentle = gentle;

        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_wake_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_wake_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            drop_pending(pend);
            warnx("could not set reply value");
            dinitctl_abort(sctl, EBADMSG);
            return;
        }
        send_reply(sctl, pend, retm);
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_wake_service_async(
            ctl, handle, pend.pin, async_cb, &pend
        ) < 0) {
            warn("dinitctl_wake_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin;

        if (!msg_get_args(
            msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &pin
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.pin = pin;

        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_release_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_release_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            drop_pending(pend);
            warnx("could not set reply value");
            dinitctl_abort(sctl, EBADMSG);
            return;
        }
        send_reply(sctl, pend, retm);
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_release_service_async(
            ctl, handle, pend.pin, async_cb, &pend
        ) < 0) {
            warn("dinitctl_release_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin;

        if (!msg_get_args(
            msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &pin
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.pin = pin;

        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_unpin_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_unpin_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_unpin_service_async(ctl, handle, async_cb, &pend) < 0) {
            warn("dinitctl_unpin_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        if (!msg_get_args(msg, DBUS_TYPE_STRING, &service_name)) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);

        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_add_remove_dep {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_add_remove_service_dependency_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        auto *to_name = static_cast<char const *>(pend.data);

        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }

        if (!pend.handle) {
            /* this is the first call */
            pend.handle = handle;
            call_load_service(pend, pend.conn, to_name, false, load_cb);
            return;
        }
        pend.handle2 = handle;

        if (dinitctl_add_remove_service_dependency_async(
            ctl, pend.handle, handle, dinitctl_dependency_type(pend.type),
            pend.remove, pend.enable, async_cb, &pend
        ) < 0) {
            warn("dinitctl_unpin_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *from_name, *to_name, *dep_type;
        dbus_bool_t remove, enable;
        int dep_typei;

        if (!msg_get_args(
            msg,
            DBUS_TYPE_STRING, &from_name,
            DBUS_TYPE_STRING, &to_name,
            DBUS_TYPE_STRING, &dep_type,
            DBUS_TYPE_BOOLEAN, &remove,
            DBUS_TYPE_BOOLEAN, &enable
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        dep_typei = str_to_enum(
            dep_type, dependency_type_str, sizeof(dependency_type_str)
        );
        if (dep_typei < 0) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.data = const_cast<char *>(to_name); /* owned by DBusMessage */
        pend.remove = remove;
        pend.enable = enable;
        pend.type = dep_typei;

        return call_load_service(pend, conn, from_name, false, load_cb);
    }
};

struct manager_get_service_dir {
    static void async_cb(dinitctl *sctl, void *data) {
        char *dir;
        ssize_t len = -1;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_get_service_directory_finish(sctl, &dir, &len);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_STRING, &dir, DBUS_TYPE_INVALID
        )) {
            drop_pending(pend);
            std::free(dir);
            warnx("could not set reply value");
            dinitctl_abort(sctl, EBADMSG);
            return;
        }
        std::free(dir);
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_get_service_directory_async(
            ctl, handle, async_cb, &pend
        ) < 0) {
            warn("dinitctl_get_service_directory_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        if (!msg_get_args(msg, DBUS_TYPE_STRING, &service_name)) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_get_service_log {
    static void async_cb(dinitctl *sctl, void *data) {
        char *log;
        ssize_t len = -1;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_get_service_log_finish(sctl, &log, &len);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_STRING, &log, DBUS_TYPE_INVALID
        )) {
            drop_pending(pend);
            std::free(log);
            warnx("could not set reply value");
            dinitctl_abort(sctl, EBADMSG);
            return;
        }
        std::free(log);
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_get_service_log_async(
            ctl, handle, pend.remove, async_cb, &pend
        ) < 0) {
            warn("dinitctl_get_service_log_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t clear;

        if (!msg_get_args(
            msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &clear
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.remove = clear;
        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

static bool append_status(
    dinitctl_service_status const &status, DBusMessageIter *iter
) {
    DBusMessageIter aiter;
    char const *str;
    dbus_int32_t estatus;
    dbus_uint32_t pid;

    auto append_flag = [&aiter](char const *key, int flags, int flag) {
        DBusMessageIter diter;
        if (!dbus_message_iter_open_container(
            &aiter, DBUS_TYPE_DICT_ENTRY, nullptr, &diter
        )) {
            return false;
        }
        if (!dbus_message_iter_append_basic(&diter, DBUS_TYPE_STRING, &key)) {
            dbus_message_iter_abandon_container(&aiter, &diter);
            return false;
        }
        dbus_bool_t val = (flags & flag) ? TRUE : FALSE;
        if (!dbus_message_iter_append_basic(&diter, DBUS_TYPE_BOOLEAN, &val)) {
            dbus_message_iter_abandon_container(&aiter, &diter);
            return false;
        }
        if (!dbus_message_iter_close_container(&aiter, &diter)) {
            dbus_message_iter_abandon_container(&aiter, &diter);
            return false;
        }
        return true;
    };

    str = enum_to_str(
        status.state, service_state_str, sizeof(service_state_str), "unknown"
    );
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str)) {
        return false;
    }
    str = enum_to_str(
        status.target_state, service_state_str, sizeof(service_state_str),
        "unknown"
    );
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str)) {
        return false;
    }
    str = enum_to_str(
        status.stop_reason, service_stop_reason_str,
        sizeof(service_stop_reason_str), "unknown"
    );
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str)) {
        return false;
    }
    str = enum_to_str(
        status.exec_stage, service_exec_stage_str,
        sizeof(service_exec_stage_str), "unknown"
    );
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str)) {
        return false;
    }
    if (!dbus_message_iter_open_container(
        iter, DBUS_TYPE_ARRAY,
        DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
            DBUS_TYPE_STRING_AS_STRING
            DBUS_TYPE_BOOLEAN_AS_STRING
        DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &aiter
    )) {
        return false;
    }
    if (!append_flag(
        "waiting_for_console", status.flags,
        DINITCTL_SERVICE_FLAG_WAITING_FOR_CONSOLE
    )) {
        dbus_message_iter_abandon_container(iter, &aiter);
        return false;
    }
    if (!append_flag(
        "has_console", status.flags,
        DINITCTL_SERVICE_FLAG_HAS_CONSOLE
    )) {
        dbus_message_iter_abandon_container(iter, &aiter);
        return false;
    }
    if (!append_flag(
        "was_start_skipped", status.flags,
        DINITCTL_SERVICE_FLAG_WAS_START_SKIPPED
    )) {
        dbus_message_iter_abandon_container(iter, &aiter);
        return false;
    }
    if (!append_flag(
        "is_marked_active", status.flags,
        DINITCTL_SERVICE_FLAG_IS_MARKED_ACTIVE
    )) {
        dbus_message_iter_abandon_container(iter, &aiter);
        return false;
    }
    if (!append_flag(
        "has_pid", status.flags,
        DINITCTL_SERVICE_FLAG_HAS_PID
    )) {
        dbus_message_iter_abandon_container(iter, &aiter);
        return false;
    }
    if (!dbus_message_iter_close_container(iter, &aiter)) {
        dbus_message_iter_abandon_container(iter, &aiter);
        return false;
    }
    pid = dbus_uint32_t(status.pid);
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &pid)) {
        return false;
    }
    estatus = dbus_int32_t(status.exit_status);
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &estatus)) {
        return false;
    }
    return true;
}

struct manager_get_service_status {
    static void async_cb(dinitctl *sctl, void *data) {
        dinitctl_service_status status;
        DBusMessageIter iter, siter;

        auto &pend = *static_cast<pending_msg *>(data);

        int ret = dinitctl_get_service_status_finish(sctl, &status);
        if (!check_error(sctl, pend, ret)) {
            return;
        }

        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }

        dbus_message_iter_init_append(retm, &iter);
        if (!dbus_message_iter_open_container(
            &iter, DBUS_TYPE_STRUCT, nullptr, &siter
        )) {
            goto container_err;
        }
        if (!append_status(status, &siter)) {
            dbus_message_iter_abandon_container(&iter, &siter);
            goto container_err;
        }
        if (!dbus_message_iter_close_container(&iter, &siter)) {
            goto container_err;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
        return;
container_err:
        drop_pending(pend);
        warnx("could not initialize reply container");
        dinitctl_abort(sctl, EBADMSG);
        return;
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_get_service_status_async(
            ctl, handle, async_cb, &pend
        ) < 0) {
            warn("dinitctl_get_service_status_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        if (!msg_get_args(msg, DBUS_TYPE_STRING, &service_name)) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        return call_load_service(pend, conn, service_name, true, load_cb);
    }
};

struct manager_set_service_trigger {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_set_service_trigger_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_set_service_trigger_async(
            ctl, handle, pend.enable, async_cb, &pend
        ) < 0) {
            warn("dinitctl_set_service_trigger_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t val;

        if (!msg_get_args(
            msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &val
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.enable = val;
        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_signal_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_signal_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        pend.handle = handle;
        if (dinitctl_signal_service_async(
            ctl, handle, pend.type, async_cb, &pend
        ) < 0) {
            warn("dinitctl_signal_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_int32_t val;

        if (!msg_get_args(
            msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_INT32, &val
        )) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.type = val;
        return call_load_service(pend, conn, service_name, false, load_cb);
    }
};

struct manager_list_services {
    static void async_cb(dinitctl *sctl, void *data) {
        ssize_t len = -1;
        dinitctl_service_list_entry *entries;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_list_services_finish(sctl, &entries, &len);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            std::free(entries);
            return;
        }
        DBusMessageIter iter, aiter;
        dbus_message_iter_init_append(retm, &iter);
        if (!dbus_message_iter_open_container(
            &iter, DBUS_TYPE_ARRAY,
            /* (sssssa{sb}ui)
             * no way around declaring this nasty signature
             */
            DBUS_STRUCT_BEGIN_CHAR_AS_STRING
                DBUS_TYPE_STRING_AS_STRING
                DBUS_TYPE_STRING_AS_STRING
                DBUS_TYPE_STRING_AS_STRING
                DBUS_TYPE_STRING_AS_STRING
                DBUS_TYPE_STRING_AS_STRING
                DBUS_TYPE_ARRAY_AS_STRING
                DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                    DBUS_TYPE_STRING_AS_STRING
                    DBUS_TYPE_BOOLEAN_AS_STRING
                DBUS_DICT_ENTRY_END_CHAR_AS_STRING
                DBUS_TYPE_UINT32_AS_STRING
                DBUS_TYPE_INT32_AS_STRING
            DBUS_STRUCT_END_CHAR_AS_STRING,
            &aiter
        )) {
            goto container_err;
        }
        for (ssize_t i = 0; i < len; ++i) {
            DBusMessageIter siter;
            if (!dbus_message_iter_open_container(
                &aiter, DBUS_TYPE_STRUCT, nullptr, &siter
            )) {
                goto container_err;
            }
            char const *nstr = entries[i].name;
            if (!dbus_message_iter_append_basic(&siter, DBUS_TYPE_STRING, &nstr)) {
                dbus_message_iter_abandon_container(&aiter, &siter);
                goto container_err;
            }
            /* now just append status, easy */
            if (!append_status(entries[i].status, &siter)) {
                dbus_message_iter_abandon_container(&aiter, &siter);
                goto container_err;
            }
            if (!dbus_message_iter_close_container(&aiter, &siter)) {
                dbus_message_iter_abandon_container(&aiter, &siter);
                goto container_err;
            }
        }
        if (!dbus_message_iter_close_container(&iter, &aiter)) {
            dbus_message_iter_abandon_container(&iter, &aiter);
            goto container_err;
        }
        if (send_reply(sctl, pend, retm)) {
            std::free(entries);
            drop_pending(pend);
        }
        return;
container_err:
        dbus_message_iter_abandon_container(&iter, &aiter);
        std::free(entries);
        drop_pending(pend);
        warnx("could not initialize reply container");
        dinitctl_abort(sctl, EBADMSG);
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        if (!msg_get_args(msg)) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        int ret = dinitctl_list_services_async(ctl, async_cb, &pend);
        if (ret < 0) {
            warn("dinitctl_list_services_async");
            drop_pending(pend);
            dinitctl_abort(ctl, EBADMSG);
            return false;
        }
        return true;
    }
};

struct manager_set_env {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_setenv_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *envs;

        if (!msg_get_args(msg, DBUS_TYPE_STRING, &envs)) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        pend.data = const_cast<char *>(envs);
        int ret = dinitctl_setenv_async(ctl, envs, async_cb, &pend);
        if (ret < 0) {
            if (errno == EINVAL) {
                drop_pending(pend);
                return msg_send_error(
                    conn, pend.msg, DBUS_ERROR_INVALID_ARGS, nullptr
                );
            }
            warn("dinitctl_setenv_async");
            drop_pending(pend);
            dinitctl_abort(ctl, EBADMSG);
            return false;
        }
        return true;
    }
};

struct manager_shutdown {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_shutdown_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            return;
        }
        if (send_reply(sctl, pend, retm)) {
            drop_pending(pend);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *type;

        if (!msg_get_args(msg, DBUS_TYPE_STRING, &type)) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }
        int stypei = str_to_enum(
            type, shutdown_type_str, sizeof(shutdown_type_str)
        );
        if (stypei < 0) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        int ret = dinitctl_shutdown_async(
            ctl, dinitctl_shutdown_type(stypei), async_cb, &pend
        );
        if (ret < 0) {
            if (errno == EINVAL) {
                drop_pending(pend);
                return msg_send_error(
                    conn, pend.msg, DBUS_ERROR_INVALID_ARGS, nullptr
                );
            }
            warn("dinitctl_shutdown_async");
            drop_pending(pend);
            dinitctl_abort(ctl, EBADMSG);
            return false;
        }
        return true;
    }
};

struct manager_query_dirs {
    static void async_cb(dinitctl *sctl, void *data) {
        size_t ndirs;
        char **dirs;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_query_service_dirs_finish(sctl, &dirs, &ndirs);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(sctl, pend);
        if (!retm) {
            std::free(dirs);
            return;
        }
        DBusMessageIter iter, aiter;
        dbus_message_iter_init_append(retm, &iter);
        if (!dbus_message_iter_open_container(
            &iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &aiter
        )) {
            goto container_err;
        }
        if (!dbus_message_iter_append_fixed_array(
            &aiter, DBUS_TYPE_STRING, &dirs, int(ndirs)
        )) {
            dbus_message_iter_abandon_container(&iter, &aiter);
            goto container_err;
        }
        if (!dbus_message_iter_close_container(&iter, &aiter)) {
            dbus_message_iter_abandon_container(&iter, &aiter);
            goto container_err;
        }
        if (send_reply(sctl, pend, retm)) {
            std::free(dirs);
            drop_pending(pend);
        }
        return;
container_err:
        dbus_message_iter_abandon_container(&iter, &aiter);
        std::free(dirs);
        drop_pending(pend);
        warnx("could not initialize reply container");
        dinitctl_abort(sctl, EBADMSG);
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        if (!msg_get_args(msg)) {
            return msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
        }

        auto &pend = add_pending(conn, msg);
        int ret = dinitctl_query_service_dirs_async(ctl, async_cb, &pend);
        if (ret < 0) {
            warn("dinitctl_query_service_dirs_async");
            drop_pending(pend);
            dinitctl_abort(ctl, EBADMSG);
            return false;
        }
        return true;
    }
};

struct manager_activate_service {
    static bool issue_failure(pending_msg &pend, char const *reason) {
        DBusMessage *ret = dbus_message_new_signal(
            BUS_OBJ, ACTIVATOR_IFACE, ACTIVATOR_FAILURE
        );
        if (!ret) {
            warnx("failed to create activation failure signal");
            drop_pending(pend);
            return false;
        }
        char const *service_name = static_cast<char *>(pend.data);
        char const *errname = ACTIVATOR_ERROR;
        if (!dbus_message_append_args(
            ret,
            DBUS_TYPE_STRING, &service_name,
            DBUS_TYPE_STRING, &errname,
            DBUS_TYPE_STRING, &reason,
            DBUS_TYPE_INVALID
        )) {
            warnx("failed to append activation failure args");
            dbus_message_unref(ret);
            drop_pending(pend);
            return false;
        }
        if (!dbus_connection_send(pend.conn, ret, nullptr)) {
            warnx("failed to send activation failure");
            dbus_message_unref(ret);
            drop_pending(pend);
            return false;
        }
        drop_pending(pend);
        return true;
    }

    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_start_service_finish(sctl);

        if (ret < 0) {
            dinitctl_abort(sctl, errno);
            drop_pending(pend);
            return;
        }

        char const *reason = nullptr;
        switch (ret) {
            case 0:
                break;
            case DINITCTL_ERROR_SHUTTING_DOWN:
                reason = "Shutting down";
                break;
            case DINITCTL_ERROR_SERVICE_PINNED:
                reason = "Service is pinned stopped";
                break;
            case DINITCTL_ERROR_SERVICE_ALREADY:
                /* actually success, end here as there is nothing else to do */
                drop_pending(pend);
                return;
            default:
                reason = "Unknown error (start)";
                break;
        }
        if (reason) {
            if (!issue_failure(pend, reason)) {
                dinitctl_abort(sctl, EBADMSG);
            }
        }
        /* now we wait for a service event, do not reply now */
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;

        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);

        if (ret < 0) {
            dinitctl_abort(sctl, errno);
            drop_pending(pend);
            return;
        }

        char const *reason = nullptr;
        switch (ret) {
            case 0:
                break;
            case DINITCTL_ERROR_SERVICE_MISSING:
                reason = "Service description not found";
                break;
            case DINITCTL_ERROR_SERVICE_DESC:
                reason = "Service description error";
                break;
            case DINITCTL_ERROR_SERVICE_LOAD:
                reason = "Service load error";
                break;
            default:
                reason = "Unknown error (load)";
                break;
        }
        if (reason) {
            if (!issue_failure(pend, reason)) {
                dinitctl_abort(sctl, EBADMSG);
            }
            return;
        }

        pend.handle = handle;
        if (dinitctl_start_service_async(
            ctl, handle, false, async_cb, &pend
        ) < 0) {
            /* we control the inputs so this is never recoverable */
            warn("dinitctl_start_service_async");
            drop_pending(pend);
            dinitctl_abort(sctl, EBADMSG);
        }
    }

    static bool invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        /* we don't know the service name, so cannot emit failure signal */
        if (!msg_get_args(msg, DBUS_TYPE_STRING, &service_name)) {
            warnx("could not get args for activation signal");
            return false;
        }

        auto &pend = add_pending(conn, msg);
        pend.data = const_cast<char *>(service_name);
        pend.is_signal = TRUE;

        int ret = dinitctl_load_service_async(
            ctl, service_name, false, load_cb, &pend
        );
        if (ret < 0) {
            if (errno == EINVAL) {
                return issue_failure(pend, "Service name too long");
            }
            warn("dinitctl_load_service_async");
            drop_pending(pend);
            return false;
        }

        return true;
    }
};

static void dinit_event_cb(
    dinitctl *sctl,
    dinitctl_service_handle *handle,
    dinitctl_service_event event,
    dinitctl_service_status const *status,
    void *
) {
    for (auto it = pending_msgs.begin(); it != pending_msgs.end(); ++it) {
        if (it->handle == handle) {
            /* event is for activation signal */
            if (it->is_signal) {
                /* emit possible activation failure here */
                char const *reason = nullptr;
                switch (event) {
                    case DINITCTL_SERVICE_EVENT_START_FAILED:
                        switch (status->stop_reason) {
                            case DINITCTL_SERVICE_STOP_REASON_DEP_FAILED:
                                reason = "Dependency has failed to start";
                                break;
                            case DINITCTL_SERVICE_STOP_REASON_TIMEOUT:
                                reason = "Service startup timed out";
                                break;
                            case DINITCTL_SERVICE_STOP_REASON_EXEC_FAILED:
                                reason = "Service process execution failed";
                                break;
                            case DINITCTL_SERVICE_STOP_REASON_FAILED:
                                reason = "Service process terminated before ready";
                                break;
                            default:
                                reason = "Service startup failed (unknown)";
                                break;
                        }
                    case DINITCTL_SERVICE_EVENT_START_CANCELED:
                        reason = "Service startup canceled";
                        break;
                    default:
                        /* consider other events successful */
                        break;
                }
                if (reason) {
                    if (!manager_activate_service::issue_failure(*it, reason)) {
                        dinitctl_abort(sctl, EBADMSG);
                    }
                } else {
                    pending_msgs.erase(it);
                }
                break;
            }
            char const *estr = enum_to_str(
                int(event), service_event_str, sizeof(service_event_str), nullptr
            );
            if (!estr) {
                pending_msgs.erase(it);
                break;
            }
            /* emit the signal here */
            DBusMessage *ret = dbus_message_new_signal(
                BUS_OBJ, BUS_IFACE, "ServiceEvent"
            );
            if (!ret) {
                pending_msgs.erase(it);
                warnx("could not create service event signal");
                dinitctl_abort(sctl, EBADMSG);
                break;
            }
            dbus_uint32_t ser = dbus_message_get_serial(it->msg);
            DBusMessageIter iter, siter;
            dbus_message_iter_init_append(ret, &iter);
            if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &ser)) {
                goto container_err;
            }
            if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &estr)) {
                goto container_err;
            }
            if (!dbus_message_iter_open_container(
                &iter, DBUS_TYPE_STRUCT, nullptr, &siter
            )) {
                goto container_err;
            }
            if (!append_status(*status, &siter)) {
                dbus_message_iter_abandon_container(&iter, &siter);
                goto container_err;
            }
            if (!dbus_message_iter_close_container(&iter, &siter)) {
                dbus_message_iter_abandon_container(&iter, &siter);
                goto container_err;
            }
            if (!dbus_connection_send(it->conn, ret, nullptr)) {
                pending_msgs.erase(it);
                warnx("could not send event signal");
                dinitctl_abort(sctl, EBADMSG);
                break;
            }
            pending_msgs.erase(it);
            break;
container_err:
            pending_msgs.erase(it);
            warnx("could not build event aguments");
            dinitctl_abort(sctl, EBADMSG);
            break;
        }
    }
}

static bool manager_method_call(
    DBusConnection *conn, DBusMessage *msg, char const *memb
) {
    if (!std::strcmp(memb, "UnloadService")) {
        return manager_unload_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "StartService")) {
        return manager_start_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "StopService")) {
        return manager_stop_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "WakeService")) {
        return manager_wake_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "ReleaseService")) {
        return manager_release_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "UnpinService")) {
        return manager_unpin_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "AddRemoveServiceDependency")) {
        return manager_add_remove_dep::invoke(conn, msg);
    } else if (!std::strcmp(memb, "GetServiceDirectory")) {
        return manager_get_service_dir::invoke(conn, msg);
    } else if (!std::strcmp(memb, "GetServiceLog")) {
        return manager_get_service_log::invoke(conn, msg);
    } else if (!std::strcmp(memb, "GetServiceStatus")) {
        return manager_get_service_status::invoke(conn, msg);
    } else if (!std::strcmp(memb, "SetServiceTrigger")) {
        return manager_set_service_trigger::invoke(conn, msg);
    } else if (!std::strcmp(memb, "SignalService")) {
        return manager_signal_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "ListServices")) {
        return manager_list_services::invoke(conn, msg);
    } else if (!std::strcmp(memb, "SetEnvironment")) {
        return manager_set_env::invoke(conn, msg);
    } else if (!std::strcmp(memb, "Shutdown")) {
        return manager_shutdown::invoke(conn, msg);
    } else if (!std::strcmp(memb, "QueryServiceDirs")) {
        return manager_query_dirs::invoke(conn, msg);
    }
    /* unknown method */
    return msg_send_error(conn, msg, DBUS_ERROR_UNKNOWN_METHOD, nullptr);
}

struct sig_data {
    int sign;
    void *data;
};

static int dbus_main(DBusConnection *conn) {
    int pret = -1;
    bool term = false;
    bool success = true;

    dbus_connection_set_exit_on_disconnect(conn, FALSE);

    if (dbus_bus_request_name(conn, BUS_NAME, 0, &dbus_err) < 0) {
        errx(1, "dbus_bus_request_name failed (%s)", dbus_err.message);
    }

    watch::setup(conn);
    timer::setup(conn);

    /* listen on activation signal from dbus */
    dbus_bus_add_match(
        conn,
        "type='signal',"
        "path='/org/freedesktop/DBus',"
        "destination='" BUS_NAME "',"
        "interface='" ACTIVATOR_IFACE "',"
        "member='" ACTIVATOR_SIGNAL "'",
        &dbus_err
    );
    if (dbus_error_is_set(&dbus_err)) {
        errx(1, "failed to register match rule (%s)", dbus_err.message);
    }

    auto filter_cb = [](
        DBusConnection *conn, DBusMessage *msg, void *datap
    ) -> DBusHandlerResult {
        if (!dbus_message_is_signal(msg, ACTIVATOR_IFACE, ACTIVATOR_SIGNAL)) {
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        bool *success = static_cast<bool *>(datap);
        /* try activating the service, don't expect reply */
        if (!manager_activate_service::invoke(conn, msg)) {
            *success = false;
        }
        return DBUS_HANDLER_RESULT_HANDLED;
    };
    if (!dbus_connection_add_filter(conn, filter_cb, &success, nullptr)) {
        errx(1, "failed to register dbus filter");
    }

    DBusObjectPathVTable vt;
    vt.message_function = [](
        DBusConnection *conn, DBusMessage *msg, void *datap
    ) {
        bool *success = static_cast<bool *>(datap);

        if (strcmp(dbus_message_get_interface(msg), BUS_IFACE)) {
            /* we only support our own interface at the moment */
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

        /* method or signal name */
        auto *memb = dbus_message_get_member(msg);

        switch (dbus_message_get_type(msg)) {
            case DBUS_MESSAGE_TYPE_METHOD_CALL:
                if (!manager_method_call(conn, msg, memb)) {
                    *success = false;
                    return DBUS_HANDLER_RESULT_HANDLED;
                }
                return DBUS_HANDLER_RESULT_HANDLED;
            case DBUS_MESSAGE_TYPE_SIGNAL:
            case DBUS_MESSAGE_TYPE_METHOD_RETURN:
            case DBUS_MESSAGE_TYPE_ERROR:
                 return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
            default:
                break;
        }

        /* fallback */
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    };
    vt.unregister_function = nullptr;

    if (!dbus_connection_try_register_object_path(
        conn, BUS_OBJ, &vt, &success, &dbus_err
    )) {
        errx(
            1, "dbus_connection_try_register_object_path failed (%s)",
            dbus_err.message
        );
    }

    /* readiness notification */
    auto ready_fd = get_fd(std::getenv("DINIT_DBUS_READY_FD"));

    /* dispatch if we have data now */
    auto cst = dbus_connection_get_dispatch_status(conn);
    if (cst == DBUS_DISPATCH_DATA_REMAINS) {
        goto do_dispatch;
    }

    while (success) {
        pret = poll(fds.data(), fds.size(), -1);
        if (pret < 0) {
            if (errno == EINTR) {
                goto do_compact;
            }
            warn("poll failed");
            success = false;
            goto do_compact;
        } else if (pret == 0) {
            goto do_compact;
        }
        /* signal fd first */
        if (fds[0].revents == POLLIN) {
            sig_data sigd;
            if (read(fds[0].fd, &sigd, sizeof(sigd)) != sizeof(sigd)) {
                warn("signal read failed");
                success = false;
                goto do_compact;
            }
            switch (sigd.sign) {
                case SIGTERM:
                case SIGINT:
                    term = true;
                    break;
                case SIGALRM: {
                    if (!static_cast<timer *>(sigd.data)->handle()) {
                        warnx("timeout handle failed");
                        success = false;
                        goto do_compact;
                    }
                }
                default:
                    break;
            }
        }
        if (term) {
            /* we're done */
            break;
        }
        /* dbus watch fds */
        for (std::size_t i = 2; i < fds.size(); ++i) {
            if (!fds[i].revents) {
                continue;
            }
            /* handle each fd */
            for (auto &w: watches) {
                if (!w.matches(fds[i])) {
                    continue;
                }
                if (!w.handle(fds[i])) {
                    warnx("watch handle failed");
                    success = false;
                    goto do_compact;
                }
                break;
            }
        }
do_dispatch:
        /* data to dispatch */
        success = true;
        for (;;) {
            auto disp = dbus_connection_get_dispatch_status(conn);
            if (disp != DBUS_DISPATCH_DATA_REMAINS) {
                break;
            }
            dbus_connection_dispatch(conn);
        }
        if (!success) {
            goto do_compact;
        }
        /* signal readiness after initial dispatch */
        if (ready_fd >= 0) {
            write(ready_fd, "READY=1\n", sizeof("READY=1"));
            close(ready_fd);
            ready_fd = -1;
        }
        for (;;) {
            int nev = dinitctl_dispatch(ctl, 0, nullptr);
            if (nev < 0) {
                if (errno == EINTR) {
                    continue;
                }
                warn("dinitctl_dispatch failed");
                success = false;
                goto do_compact;
            } else if (!nev) {
                break;
            }
        }
do_compact:
        for (auto it = fds.begin(); it != fds.end();) {
            if (it->fd == -1) {
                it = fds.erase(it);
            } else {
                ++it;
            }
        }
    }
    /* do it before closing dinitctl so dtors don't mess it up */
    pending_msgs.clear();
    dinitctl_close(ctl);
    /* try to perform an orderly shutdown */
    for (auto &fd: fds) {
        if (fd.fd >= 0) {
            close(fd.fd);
        }
    }
    /* finally unref the dbus connection */
    dbus_connection_unref(conn);
    return 0;
}

int main(int argc, char **argv) {
    char const *addr = nullptr;
    char const *sockp = nullptr;
    DBusBusType bt = DBUS_BUS_SESSION;
    int dinit_fd = -1;
    static int sigpipe[2];

    watches.reserve(4);
    timers.reserve(4);
    fds.reserve(16);
    pending_msgs.reserve(8);

    for (int c; (c = getopt(argc, argv, "a:f:hS:s")) > 0;) {
        switch (c) {
            case 'h':
                usage(stdout);
                return 0;
            case 'a':
                addr = optarg;
                break;
            case 'f':
                dinit_fd = get_fd(optarg);
                if (dinit_fd < 0) {
                    errx(1, "invalid file descriptor given");
                }
                break;
            case 'S':
                sockp = optarg;
                break;
            case 's':
                bt = DBUS_BUS_SYSTEM;
                break;
            default:
                std::fprintf(stderr, "\n");
                usage(stderr);
                return 1;
        }
    }

    /* if no fd and socket given, try to connect */
    if ((dinit_fd < 0) && sockp) {
        sockaddr_un saddr;
        auto slen = std::strlen(sockp);

        if (slen >= sizeof(saddr.sun_path)) {
            errx(1, "socket path too long");
        }

        dinit_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (dinit_fd < 0) {
            err(1, "socket failed");
        }

        std::memset(&saddr, 0, sizeof(saddr));

        saddr.sun_family = AF_UNIX;
        std::memcpy(saddr.sun_path, sockp, slen);

        auto *sp = reinterpret_cast<sockaddr const *>(&saddr);
        if (connect(dinit_fd, sp, sizeof(saddr)) < 0) {
            err(1, "connect failed");
        }
    }

    /* else try env var */
    if (dinit_fd < 0) {
        dinit_fd = get_fd(std::getenv("DINIT_CS_FD"));
    }

    /* still nothing? */
    if (dinit_fd < 0) {
        errx(1, "no file descriptor");
    }

    /* set up the C API */
    ctl = dinitctl_open_fd(dinit_fd);
    if (!ctl) {
        err(1, "failed to set up dinitctl");
    }

    dinitctl_set_service_event_callback(ctl, dinit_event_cb, nullptr);

    /* signal pipe */
    if (pipe(sigpipe) < 0) {
        err(1, "pipe failed");
    }
    if (
        (fcntl(sigpipe[0], F_SETFD, FD_CLOEXEC) < 0) ||
        (fcntl(sigpipe[1], F_SETFD, FD_CLOEXEC) < 0)
    ) {
        err(1, "fcntl failed");
    }
    auto &spfd = fds.emplace_back();
    spfd.fd = sigpipe[0];
    spfd.events = POLLIN;
    spfd.revents = 0;

    /* ctl pollfd */
    auto &cfd = fds.emplace_back();
    cfd.fd = dinitctl_get_fd(ctl);
    cfd.events = POLLIN | POLLHUP;
    cfd.revents = 0;

    /* signal action */
    {
        struct sigaction sa{};
        sa.sa_handler = [](int sign) {
            sig_data d;
            d.sign = sign;
            d.data = nullptr;
            write(sigpipe[1], &d, sizeof(d));
        };
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGINT, &sa, nullptr);
    }

    /* timer action for timeouts */
    {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sa.sa_sigaction = [](int sign, siginfo_t *si, void *) {
            sig_data d;
            d.sign = sign;
            d.data = si->si_value.sival_ptr;
            write(sigpipe[1], &d, sizeof(d));
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGALRM, &sa, nullptr);
    }

    dbus_error_init(&dbus_err);

    DBusConnection *conn;

    /* before we set up a main loop, establish a connection */
    if (addr) {
        conn = dbus_connection_open(addr, &dbus_err);
    } else {
        conn = dbus_bus_get(bt, &dbus_err);
    }
    if (!conn) {
        errx(1, "connection error (%s)", dbus_err.message);
    }

    return dbus_main(conn);
}
