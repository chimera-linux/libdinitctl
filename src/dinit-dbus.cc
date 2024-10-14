/*
 * A control interface for dinit on D-Bus.
 *
 * This implements an equivalent of the C API on the bus. It's meant
 * t run as a daemon launched from a dinit service (with pass-cs-fd).
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
#include <cassert>
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

#if 1
#define ACTIVATOR_TARGET "/org/freedesktop/DBus"
#define ACTIVATOR_DEST "org.freedesktop.DBus"
#else
#define ACTIVATOR_TARGET BUS_OBJ
#define ACTIVATOR_DEST BUS_NAME
#endif
#define ACTIVATOR_IFACE BUS_NAME ".Activator"
#define ACTIVATOR_SIGNAL "ActivationRequest"
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
            watches.emplace_back(w).enable();
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
        fds.emplace_back(pfd);
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
            timers.emplace_back(t, ret).arm();
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
    pending_msg *next = nullptr;
    void *data;
    char **darray = nullptr;
    int type, idx;
    dbus_bool_t reload, pin, gentle, remove, enable, is_signal = FALSE;

    pending_msg():
        conn{nullptr}, msg{nullptr}
    {}
    pending_msg(DBusConnection *c, DBusMessage *p):
        conn{c}, msg{dbus_message_ref(p)}
    {}
    pending_msg(pending_msg const &) = delete;
    pending_msg(pending_msg &&v) = delete;
    ~pending_msg() {
        if (darray) {
            dbus_free_string_array(darray);
        }
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
    pending_msg &operator=(pending_msg &&v) = delete;
};

struct msg_list {
    static constexpr std::size_t chksize = 8;

    struct chunk {
        pending_msg msg[chksize];
        chunk *next;
    };
    chunk *chunk_avail = nullptr;
    pending_msg *msg_unused = nullptr, *msg_top = nullptr;

    ~msg_list() {
        clear();
    }

    void clear() {
        while (chunk_avail) {
            auto *chk = chunk_avail;
            chunk_avail = chk->next;
            for (std::size_t i = 0; i < chksize; ++i) {
                chk->msg[i].~pending_msg();
            }
            std::free(chk);
        }
        chunk_avail = nullptr;
        msg_unused = msg_top = nullptr;
    }

    pending_msg *reserve_chunk() {
        chunk *chk = static_cast<chunk *>(calloc(1, sizeof(chunk)));
        if (!chk) {
            throw std::bad_alloc{};
        }
        for (std::size_t i = 0; i < (chksize - 1); ++i) {
            new (&chk->msg[i]) pending_msg{};
            chk->msg[i].next = &chk->msg[i + 1];
        }
        new (&chk->msg[chksize - 1]) pending_msg{};
        chk->msg[chksize - 1].next = msg_unused;
        chk->next = chunk_avail;
        chunk_avail = chk;
        msg_unused = chk->msg;
        return msg_unused;
    }

    pending_msg &add(DBusConnection *conn, DBusMessage *msg) {
        auto *p = msg_unused;
        if (!p) {
            p = reserve_chunk();
        }
        msg_unused = msg_unused->next;
        p->~pending_msg();
        new (p) pending_msg{conn, msg};
        p->next = msg_top;
        msg_top = p;
        return *p;
    }

    pending_msg *begin() const {
        return msg_top;
    }

    void drop(pending_msg &p) {
        auto *pp = &p;
        if (pp == msg_top) {
            drop_at(nullptr, p);
            return;
        }
        auto *prevp = msg_top, *curp = prevp->next;
        while (curp) {
            if (curp == pp) {
                drop_at(prevp, p);
                return;
            }
            prevp = curp;
            curp = curp->next;
        }
        /* should be unreachable */
        assert(false);
    }

    void drop_at(pending_msg *pp, pending_msg &p) {
        if (!pp) {
            msg_top = p.next;
        } else {
            pp->next = p.next;
        }
        p.~pending_msg();
        new (&p) pending_msg{};
        p.next = msg_unused;
        msg_unused = pp;
    }
};

static msg_list pending_msgs;

template<typename ...A>
static bool msg_get_args(DBusMessage *msg, A const &...args) {
    if (!dbus_message_get_args(msg, &dbus_err, args..., DBUS_TYPE_INVALID)) {
        if (dbus_error_has_name(&dbus_err, DBUS_ERROR_NO_MEMORY)) {
            throw std::bad_alloc{};
        }
        dbus_error_free(&dbus_err);
        return false;
    }
    return true;
}

#define MSG_NO_ARGS(conn, msg) \
    if (!msg_get_args(msg)) { \
        msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr); \
        return; \
    }

#define MSG_GET_ARGS(conn, msg, ...) \
    if (!msg_get_args(msg, __VA_ARGS__)) { \
        msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr); \
        return; \
    }

static void msg_send_error(
    DBusConnection *conn, DBusMessage *msg, char const *err, char const *desc
) {
    DBusMessage *ret = dbus_message_new_error(msg, err, desc);
    if (!ret || !dbus_connection_send(conn, ret, nullptr)) {
        warnx("dbus_connection_send failed");
        if (ret) {
            dbus_message_unref(ret);
        }
        throw std::bad_alloc{};
    }
    dbus_message_unref(ret);
}

static void msg_reply_error(
    pending_msg &pend, char const *err, char const *desc
) {
    msg_send_error(pend.conn, pend.msg, err, desc);
    pending_msgs.drop(pend);
}

static DBusMessage *msg_new_reply(pending_msg &pend) {
    if (dbus_message_get_no_reply(pend.msg)) {
        pending_msgs.drop(pend);
        return nullptr;
    }
    DBusMessage *retm = dbus_message_new_method_return(pend.msg);
    if (!retm) {
        throw std::bad_alloc{};
    }
    return retm;
}

static bool check_error(dinitctl *sctl, pending_msg &pend, int ret) {
    if (ret < 0) {
        if (errno == ENOMEM) throw std::bad_alloc{};
        dinitctl_abort(sctl, errno);
        pending_msgs.drop(pend);
        return false;
    } else if (ret) {
        auto *err = enum_to_str(ret, error_str, sizeof(error_str), nullptr);
        if (!err) {
            warn("unknown dinitctl error");
            dinitctl_abort(sctl, EBADMSG);
        } else {
            msg_send_error(pend.conn, pend.msg, err, nullptr);
        }
        pending_msgs.drop(pend);
        return false;
    }
    return true;
}

static void send_reply(pending_msg &pend, DBusMessage *retm) {
    if (!dbus_connection_send(pend.conn, retm, nullptr)) {
        throw std::bad_alloc{};
    }
    dbus_message_unref(retm);
    pending_msgs.drop(pend);
}

static void call_load_service(
    pending_msg &pend, char const *service_name, bool find, dinitctl_async_cb cb
) {
    int ret = dinitctl_load_service_async(ctl, service_name, find, cb, &pend);
    if (ret < 0) {
        if (errno == EINVAL) {
            msg_reply_error(pend, DBUS_ERROR_INVALID_ARGS, nullptr);
            return;
        }
        /* only other error is ENOMEM */
        throw std::bad_alloc{};
    }
}

struct manager_unload_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_unload_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
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
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t reload;

        MSG_GET_ARGS(
            conn, msg,
            DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &reload
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.reload = reload;

        call_load_service(pend, service_name, true, load_cb);
    }
};

struct manager_start_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_start_service_finish(sctl, NULL);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            throw std::bad_alloc{};
        }
        send_reply(pend, retm);
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
            ctl, handle, pend.pin, false, async_cb, &pend
        ) < 0) {
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &pin
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.pin = pin;

        call_load_service(pend, service_name, false, load_cb);
    }
};

struct manager_stop_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_stop_service_finish(sctl, NULL);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            throw std::bad_alloc{};
        }
        send_reply(pend, retm);
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
            ctl, handle, pend.pin, pend.reload, pend.gentle, false, async_cb, &pend
        ) < 0) {
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin, restart, gentle;

        MSG_GET_ARGS(
            conn, msg,
            DBUS_TYPE_STRING, &service_name,
            DBUS_TYPE_BOOLEAN, &pin,
            DBUS_TYPE_BOOLEAN, &restart,
            DBUS_TYPE_BOOLEAN, &gentle
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.pin = pin;
        pend.reload = restart;
        pend.gentle = gentle;

        call_load_service(pend, service_name, false, load_cb);
    }
};

struct manager_wake_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_wake_service_finish(sctl, NULL);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            throw std::bad_alloc{};
        }
        send_reply(pend, retm);
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
            ctl, handle, pend.pin, false, async_cb, &pend
        ) < 0) {
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &pin
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.pin = pin;

        call_load_service(pend, service_name, false, load_cb);
    }
};

struct manager_release_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_release_service_finish(sctl, NULL);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pend.msg);
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_UINT32, &ser, DBUS_TYPE_INVALID
        )) {
            throw std::bad_alloc{};
        }
        send_reply(pend, retm);
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
            ctl, handle, pend.pin, false, async_cb, &pend
        ) < 0) {
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t pin;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &pin
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.pin = pin;

        call_load_service(pend, service_name, false, load_cb);
    }
};

struct manager_unpin_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_unpin_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
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
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        MSG_GET_ARGS(conn, msg, DBUS_TYPE_STRING, &service_name)

        auto &pend = pending_msgs.add(conn, msg);
        call_load_service(pend, service_name, false, load_cb);
    }
};

struct manager_add_remove_dep {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_add_remove_service_dependency_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
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
            call_load_service(pend, to_name, false, load_cb);
            return;
        }
        pend.handle2 = handle;

        if (dinitctl_add_remove_service_dependency_async(
            ctl, pend.handle, handle, dinitctl_dependency_type(pend.type),
            pend.remove, pend.enable, async_cb, &pend
        ) < 0) {
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *from_name, *to_name, *dep_type;
        dbus_bool_t remove, enable;
        int dep_typei;

        MSG_GET_ARGS(
            conn, msg,
            DBUS_TYPE_STRING, &from_name,
            DBUS_TYPE_STRING, &to_name,
            DBUS_TYPE_STRING, &dep_type,
            DBUS_TYPE_BOOLEAN, &remove,
            DBUS_TYPE_BOOLEAN, &enable
        )

        dep_typei = str_to_enum(
            dep_type, dependency_type_str, sizeof(dependency_type_str)
        );
        if (dep_typei < 0) {
            msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
            return;
        }

        auto &pend = pending_msgs.add(conn, msg);
        pend.data = const_cast<char *>(to_name); /* owned by DBusMessage */
        pend.remove = remove;
        pend.enable = enable;
        pend.type = dep_typei;

        call_load_service(pend, from_name, false, load_cb);
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
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_STRING, &dir, DBUS_TYPE_INVALID
        )) {
            throw std::bad_alloc{};
        }
        std::free(dir);
        send_reply(pend, retm);
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
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        MSG_GET_ARGS(conn, msg, DBUS_TYPE_STRING, &service_name)

        auto &pend = pending_msgs.add(conn, msg);
        call_load_service(pend, service_name, false, load_cb);
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
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        if (!dbus_message_append_args(
            retm, DBUS_TYPE_STRING, &log, DBUS_TYPE_INVALID
        )) {
            throw std::bad_alloc{};
        }
        std::free(log);
        send_reply(pend, retm);
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
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t clear;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &clear
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.remove = clear;

        call_load_service(pend, service_name, false, load_cb);
    }
};

static bool append_status(
    dinitctl_service_status const &status, DBusMessageIter *iter
) {
    DBusMessageIter aiter;
    char const *str;
    dbus_int32_t estatus, ecode;
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
        return false;
    }
    pid = dbus_uint32_t(status.pid);
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &pid)) {
        return false;
    }
    ecode = dbus_int32_t(status.exit_code);
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &ecode)) {
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

        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }

        dbus_message_iter_init_append(retm, &iter);
        if (!dbus_message_iter_open_container(
            &iter, DBUS_TYPE_STRUCT, nullptr, &siter
        )) {
            throw std::bad_alloc{};
        }
        if (!append_status(status, &siter)) {
            dbus_message_iter_abandon_container(&iter, &siter);
            throw std::bad_alloc{};
        }
        if (!dbus_message_iter_close_container(&iter, &siter)) {
            throw std::bad_alloc{};
        }
        send_reply(pend, retm);
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
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        MSG_GET_ARGS(conn, msg, DBUS_TYPE_STRING, &service_name)

        auto &pend = pending_msgs.add(conn, msg);
        call_load_service(pend, service_name, true, load_cb);
    }
};

struct manager_set_service_trigger {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_set_service_trigger_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
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
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_bool_t val;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_BOOLEAN, &val
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.enable = val;

        call_load_service(pend, service_name, false, load_cb);
    }
};

struct manager_signal_service {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_signal_service_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
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
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;
        dbus_int32_t val;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_STRING, &service_name, DBUS_TYPE_INT32, &val
        )

        auto &pend = pending_msgs.add(conn, msg);
        pend.type = val;

        call_load_service(pend, service_name, false, load_cb);
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
        DBusMessage *retm = msg_new_reply(pend);
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
                DBUS_TYPE_INT32_AS_STRING
            DBUS_STRUCT_END_CHAR_AS_STRING,
            &aiter
        )) {
            std::free(entries);
            throw std::bad_alloc{};
        }
        for (ssize_t i = 0; i < len; ++i) {
            DBusMessageIter siter;
            if (!dbus_message_iter_open_container(
                &aiter, DBUS_TYPE_STRUCT, nullptr, &siter
            )) {
                std::free(entries);
                throw std::bad_alloc{};
            }
            char const *nstr = entries[i].name;
            if (!dbus_message_iter_append_basic(&siter, DBUS_TYPE_STRING, &nstr)) {
                dbus_message_iter_abandon_container(&aiter, &siter);
                std::free(entries);
                throw std::bad_alloc{};
            }
            /* now just append status, easy */
            if (!append_status(entries[i].status, &siter)) {
                dbus_message_iter_abandon_container(&aiter, &siter);
                std::free(entries);
                throw std::bad_alloc{};
            }
            if (!dbus_message_iter_close_container(&aiter, &siter)) {
                std::free(entries);
                throw std::bad_alloc{};
            }
        }
        if (!dbus_message_iter_close_container(&iter, &aiter)) {
                std::free(entries);
                throw std::bad_alloc{};
        }
        send_reply(pend, retm);
        std::free(entries);
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        MSG_NO_ARGS(conn, msg)

        auto &pend = pending_msgs.add(conn, msg);
        int ret = dinitctl_list_services_async(ctl, async_cb, &pend);
        if (ret < 0) {
            throw std::bad_alloc{};
        }
    }
};

struct manager_set_env {
    static bool setenv_async(
        dinitctl *ctl, char const *env, dinitctl_async_cb cb, void *data
    ) {
        /* over dbus one must always supply value */
        if (!std::strchr(env, '=')) {
            return (dinitctl_unsetenv_async(ctl, env, cb, data) >= 0);
        }
        return (dinitctl_setenv_async(ctl, env, cb, data) >= 0);
    }

    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        /* same underlying message, simplify things for ourselves... */
        int ret = dinitctl_setenv_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        if (++pend.idx < pend.type) {
            /* send the next one */
            if (setenv_async(sctl, pend.darray[pend.idx], async_cb, data)) {
                /* success, take over from next cb */
                return;
            }
            /* error here */
            if (errno == EINVAL) {
                msg_reply_error(pend, DBUS_ERROR_INVALID_ARGS, nullptr);
            } else {
                /* only ENOMEM is possible */
                throw std::bad_alloc{};
            }
            return;
        }
        /* final reply */
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char **envs = nullptr;
        int nenvs;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &envs, &nenvs
        )

        if (nenvs == 0) {
            /* reply right away */
            if (dbus_message_get_no_reply(msg)) {
                dbus_free_string_array(envs);
                return;
            }
            DBusMessage *retm = dbus_message_new_method_return(msg);
            if (!retm || !dbus_connection_send(conn, retm, nullptr)) {
                dbus_free_string_array(envs);
                throw std::bad_alloc{};
            }
            dbus_message_unref(retm);
            return;
        }

        auto &pend = pending_msgs.add(conn, msg);
        pend.darray = envs;
        pend.type = nenvs;
        pend.idx = 0;
        if (!setenv_async(ctl, envs[0], async_cb, &pend)) {
            if (errno == EINVAL) {
                msg_reply_error(pend, DBUS_ERROR_INVALID_ARGS, nullptr);
                return;
            }
            throw std::bad_alloc{};
        }
    }
};

struct manager_get_all_env {
    static void async_cb(dinitctl *sctl, void *data) {
        size_t bsize;
        char *vars;
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_get_all_env_finish(sctl, &vars, &bsize);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            std::free(vars);
            return;
        }
        DBusMessageIter iter, aiter;
        dbus_message_iter_init_append(retm, &iter);
        if (!dbus_message_iter_open_container(
            &iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &aiter
        )) {
            std::free(vars);
            throw std::bad_alloc{};
        }
        for (char *curvar = vars; bsize;) {
            if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &curvar)) {
                throw std::bad_alloc{};
            }
            auto slen = std::strlen(curvar);
            curvar += slen + 1;
            bsize -= slen + 1;
        }
        if (!dbus_message_iter_close_container(&iter, &aiter)) {
            std::free(vars);
            throw std::bad_alloc{};
        }
        send_reply(pend, retm);
        std::free(vars);
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        MSG_NO_ARGS(conn, msg)

        auto &pend = pending_msgs.add(conn, msg);
        int ret = dinitctl_get_all_env_async(ctl, async_cb, &pend);
        if (ret < 0) {
            throw std::bad_alloc{};
        }
    }
};

struct manager_shutdown {
    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_shutdown_finish(sctl);
        if (!check_error(sctl, pend, ret)) {
            return;
        }
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *type;

        MSG_GET_ARGS(conn, msg, DBUS_TYPE_STRING, &type)

        int stypei = str_to_enum(
            type, shutdown_type_str, sizeof(shutdown_type_str)
        );
        if (stypei < 0) {
            msg_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, nullptr);
            return;
        }

        auto &pend = pending_msgs.add(conn, msg);
        int ret = dinitctl_shutdown_async(
            ctl, dinitctl_shutdown_type(stypei), async_cb, &pend
        );
        if (ret < 0) {
            if (errno == EINVAL) {
                msg_reply_error(pend, DBUS_ERROR_INVALID_ARGS, nullptr);
                return;
            }
            throw std::bad_alloc{};
        }
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
        DBusMessage *retm = msg_new_reply(pend);
        if (!retm) {
            std::free(dirs);
            return;
        }
        DBusMessageIter iter, aiter;
        dbus_message_iter_init_append(retm, &iter);
        if (!dbus_message_iter_open_container(
            &iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &aiter
        )) {
            std::free(dirs);
            throw std::bad_alloc{};
        }
        if (!dbus_message_iter_append_fixed_array(
            &aiter, DBUS_TYPE_STRING, &dirs, int(ndirs)
        )) {
            dbus_message_iter_abandon_container(&iter, &aiter);
            std::free(dirs);
            throw std::bad_alloc{};
        }
        if (!dbus_message_iter_close_container(&iter, &aiter)) {
            std::free(dirs);
            throw std::bad_alloc{};
        }
        send_reply(pend, retm);
        std::free(dirs);
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        MSG_NO_ARGS(conn, msg)

        auto &pend = pending_msgs.add(conn, msg);
        int ret = dinitctl_query_service_dirs_async(ctl, async_cb, &pend);
        if (ret < 0) {
            throw std::bad_alloc{};
        }
    }
};

struct manager_activate_service {
    static void issue_failure(pending_msg &pend, char const *reason) {
        DBusMessage *ret = dbus_message_new_signal(
            BUS_OBJ, ACTIVATOR_IFACE, ACTIVATOR_FAILURE
        );
        if (!ret) {
            throw std::bad_alloc{};
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
            throw std::bad_alloc{};
        }
        if (!dbus_message_set_destination(ret, ACTIVATOR_DEST)) {
            warnx("failed set failure destination");
            dbus_message_unref(ret);
            throw std::bad_alloc{};
        }
        if (!dbus_connection_send(pend.conn, ret, nullptr)) {
            warnx("failed to send activation failure");
            dbus_message_unref(ret);
            throw std::bad_alloc{};
        }
        pending_msgs.drop(pend);
    }

    static void async_cb(dinitctl *sctl, void *data) {
        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_start_service_finish(sctl, NULL);

        if (ret < 0) {
            dinitctl_abort(sctl, errno);
            pending_msgs.drop(pend);
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
                pending_msgs.drop(pend);
                return;
            default:
                reason = "Unknown error (start)";
                break;
        }
        if (reason) {
            issue_failure(pend, reason);
        }
        /* now we wait for a service event, do not reply now */
    }

    static void load_cb(dinitctl *sctl, void *data) {
        dinitctl_service_handle *handle;

        auto &pend = *static_cast<pending_msg *>(data);
        int ret = dinitctl_load_service_finish(sctl, &handle, nullptr, nullptr);

        if (ret < 0) {
            dinitctl_abort(sctl, errno);
            pending_msgs.drop(pend);
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
            issue_failure(pend, reason);
            return;
        }

        pend.handle = handle;
        if (dinitctl_start_service_async(
            ctl, handle, false, false, async_cb, &pend
        ) < 0) {
            /* only ENOMEM is possible */
            throw std::bad_alloc{};
        }
    }

    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *service_name;

        /* we don't know the service name, so cannot emit failure signal */
        if (!msg_get_args(msg, DBUS_TYPE_STRING, &service_name)) {
            /* ignore malformed signal... */
            return;
        }

        auto &pend = pending_msgs.add(conn, msg);
        pend.data = const_cast<char *>(service_name);
        pend.is_signal = TRUE;

        int ret = dinitctl_load_service_async(
            ctl, service_name, false, load_cb, &pend
        );
        if (ret < 0) {
            if (errno == EINVAL) {
                issue_failure(pend, "Service name too long");
                return;
            }
            throw std::bad_alloc{};
        }
    }
};

struct manager_create_ephemeral_service {
    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *name;
        char const *contents;
        DBusMessage *retm;

        MSG_GET_ARGS(
            conn, msg, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &contents
        )

        auto &pend = pending_msgs.add(conn, msg);

        FILE *f = dinitctl_create_ephemeral_service(ctl, name);
        if (!f) {
            /* XXX: better error for EBADF? */
            if ((errno == ENOENT) || (errno == EBADF)) {
                msg_reply_error(pend, DBUS_ERROR_FILE_NOT_FOUND, nullptr);
                return;
            }
            /* FIXME this may be different errors */
            throw std::bad_alloc{};
        }

        auto slen = std::strlen(contents);

        if (fwrite(contents, 1, slen, f) != slen) {
            std::fclose(f);
            /* make sure to drop it first since it's incomplete */
            dinitctl_remove_ephemeral_service(ctl, name);
            /* then send a recoverable error */
            msg_reply_error(pend, DBUS_ERROR_IO_ERROR, nullptr);
            return;
        }
        std::fclose(f);

        retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
    }
};

struct manager_remove_ephemeral_service {
    static void invoke(DBusConnection *conn, DBusMessage *msg) {
        char const *name;
        DBusMessage *retm;

        MSG_GET_ARGS(conn, msg, DBUS_TYPE_STRING, &name)

        auto &pend = pending_msgs.add(conn, msg);

        if (dinitctl_remove_ephemeral_service(ctl, name) < 0) {
            if ((errno == ENOENT) || (errno == EBADF)) {
                msg_reply_error(pend, DBUS_ERROR_FILE_NOT_FOUND, nullptr);
                return;
            }
            /* FIXME this may be different errors */
            throw std::bad_alloc{};
        }

        retm = msg_new_reply(pend);
        if (!retm) {
            return;
        }
        send_reply(pend, retm);
    }
};

static void dinit_sv_event_cb(
    dinitctl *sctl,
    dinitctl_service_handle *handle,
    dinitctl_service_event event,
    dinitctl_service_status const *status,
    void *
) {
    auto *pp = pending_msgs.begin();
    pending_msg *prevp = nullptr;
    while (pp) {
        if (pp->handle != handle) {
            prevp = pp;
            pp = pp->next;
            continue;
        }
        /* event is for activation signal */
        if (pp->is_signal) {
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
                    break;
                case DINITCTL_SERVICE_EVENT_START_CANCELED:
                    reason = "Service startup canceled";
                    break;
                default:
                    /* consider other events successful */
                    break;
            }
            if (reason) {
                manager_activate_service::issue_failure(*pp, reason);
            } else {
                pending_msgs.drop_at(prevp, *pp);
            }
            break;
        }
        char const *estr = enum_to_str(
            int(event), service_event_str, sizeof(service_event_str), nullptr
        );
        if (!estr) {
            pending_msgs.drop_at(prevp, *pp);
            break;
        }
        /* emit the signal here */
        DBusMessage *ret = dbus_message_new_signal(
            BUS_OBJ, BUS_IFACE, "ServiceEvent"
        );
        if (!ret) {
            pending_msgs.drop_at(prevp, *pp);
            warnx("could not create service event signal");
            dinitctl_abort(sctl, EBADMSG);
            break;
        }
        dbus_uint32_t ser = dbus_message_get_serial(pp->msg);
        DBusMessageIter iter, siter;
        dbus_message_iter_init_append(ret, &iter);
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &ser)) {
            throw std::bad_alloc{};
        }
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &estr)) {
            throw std::bad_alloc{};
        }
        if (!dbus_message_iter_open_container(
            &iter, DBUS_TYPE_STRUCT, nullptr, &siter
        )) {
            throw std::bad_alloc{};
        }
        if (!append_status(*status, &siter)) {
            dbus_message_iter_abandon_container(&iter, &siter);
            throw std::bad_alloc{};
        }
        if (!dbus_message_iter_close_container(&iter, &siter)) {
            throw std::bad_alloc{};
        }
        if (!dbus_connection_send(pp->conn, ret, nullptr)) {
            throw std::bad_alloc{};
        }
        pending_msgs.drop_at(prevp, *pp);
        break;
    }
}

static void dinit_env_event_cb(
    dinitctl *sctl,
    char const *env,
    int flags,
    void *data
) {
    auto *conn = static_cast<DBusConnection *>(data);
    /* emit the signal here */
    DBusMessage *ret = dbus_message_new_signal(
        BUS_OBJ, BUS_IFACE, "EnvironmentEvent"
    );
    if (!ret) {
        warnx("could not create environment event signal");
        dinitctl_abort(sctl, EBADMSG);
        return;
    }
    dbus_bool_t over = (flags != 0);
    DBusMessageIter iter;
    dbus_message_iter_init_append(ret, &iter);
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &env)) {
        throw std::bad_alloc{};
    }
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &over)) {
        throw std::bad_alloc{};
    }
    if (!dbus_connection_send(conn, ret, nullptr)) {
        warnx("could not send event signal");
        dinitctl_abort(sctl, EBADMSG);
    }
}

static void manager_method_call(
    DBusConnection *conn, DBusMessage *msg, char const *memb
) {
    if (!std::strcmp(memb, "UnloadService")) {
        manager_unload_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "StartService")) {
        manager_start_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "StopService")) {
        manager_stop_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "WakeService")) {
        manager_wake_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "ReleaseService")) {
        manager_release_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "UnpinService")) {
        manager_unpin_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "AddRemoveServiceDependency")) {
        manager_add_remove_dep::invoke(conn, msg);
    } else if (!std::strcmp(memb, "GetServiceDirectory")) {
        manager_get_service_dir::invoke(conn, msg);
    } else if (!std::strcmp(memb, "GetServiceLog")) {
        manager_get_service_log::invoke(conn, msg);
    } else if (!std::strcmp(memb, "GetServiceStatus")) {
        manager_get_service_status::invoke(conn, msg);
    } else if (!std::strcmp(memb, "SetServiceTrigger")) {
        manager_set_service_trigger::invoke(conn, msg);
    } else if (!std::strcmp(memb, "SignalService")) {
        manager_signal_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "ListServices")) {
        manager_list_services::invoke(conn, msg);
    } else if (!std::strcmp(memb, "SetEnvironment")) {
        manager_set_env::invoke(conn, msg);
    } else if (!std::strcmp(memb, "GetAllEnvironment")) {
        manager_get_all_env::invoke(conn, msg);
    } else if (!std::strcmp(memb, "Shutdown")) {
        manager_shutdown::invoke(conn, msg);
    } else if (!std::strcmp(memb, "QueryServiceDirs")) {
        manager_query_dirs::invoke(conn, msg);
    } else if (!std::strcmp(memb, "CreateEphemeralService")) {
        manager_create_ephemeral_service::invoke(conn, msg);
    } else if (!std::strcmp(memb, "RemoveEphemeralService")) {
        manager_remove_ephemeral_service::invoke(conn, msg);
    } else {
        /* unknown method */
        msg_send_error(conn, msg, DBUS_ERROR_UNKNOWN_METHOD, nullptr);
    }
}

struct sig_data {
    int sign;
    void *data;
};

static void dbus_main(DBusConnection *conn) {
    int pret = -1;
    bool term = false;

    /* readiness notification */
    auto ready_fd = get_fd(std::getenv("DINIT_DBUS_READY_FD"));

    /* dispatch if we have data now */
    auto cst = dbus_connection_get_dispatch_status(conn);
    if (cst == DBUS_DISPATCH_DATA_REMAINS) {
        goto do_dispatch;
    }

    for (;;) {
        pret = poll(fds.data(), fds.size(), -1);
        if (pret < 0) {
            if (errno == EINTR) {
                continue;
            }
            warn("poll failed");
            return;
        } else if (pret == 0) {
            continue;
        }
        /* signal fd first */
        if (fds[0].revents == POLLIN) {
            sig_data sigd;
            if (read(fds[0].fd, &sigd, sizeof(sigd)) != sizeof(sigd)) {
                warn("signal read failed");
                return;
            }
            switch (sigd.sign) {
                case SIGTERM:
                case SIGINT:
                    term = true;
                    break;
                case SIGALRM: {
                    if (!static_cast<timer *>(sigd.data)->handle()) {
                        warnx("timeout handle failed");
                        return;
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
                    return;
                }
                break;
            }
        }
do_dispatch:
        /* data to dispatch */
        for (;;) {
            auto disp = dbus_connection_get_dispatch_status(conn);
            if (disp != DBUS_DISPATCH_DATA_REMAINS) {
                break;
            }
            dbus_connection_dispatch(conn);
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
                return;
            } else if (!nev) {
                break;
            }
        }
        /* compact any fds after dispatch */
        for (auto it = fds.begin(); it != fds.end();) {
            if (it->fd == -1) {
                it = fds.erase(it);
            } else {
                ++it;
            }
        }
    }
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
    if (!pending_msgs.reserve_chunk()) {
        err(1, "out of memory");
    }

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

    if (dinitctl_set_service_event_callback(ctl, dinit_sv_event_cb, nullptr) < 0) {
        err(1, "failed to set event callback");
    }

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

    if (dinitctl_set_env_event_callback(ctl, dinit_env_event_cb, conn) < 0) {
        err(1, "failed to set environment callback");
    }

    if ((dinitctl_setup_ephemeral_directory(ctl) < 0) && (errno != ENOENT)) {
        err(1, "failed to set up ephemeral service directory");
    }

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
        "path='" ACTIVATOR_TARGET "',"
        "destination='" BUS_NAME "',"
        "interface='" ACTIVATOR_IFACE "',"
        "member='" ACTIVATOR_SIGNAL "'",
        &dbus_err
    );
    if (dbus_error_is_set(&dbus_err)) {
        errx(1, "failed to register match rule (%s)", dbus_err.message);
    }

    auto filter_cb = [](
        DBusConnection *conn, DBusMessage *msg, void *
    ) -> DBusHandlerResult {
        if (!dbus_message_is_signal(msg, ACTIVATOR_IFACE, ACTIVATOR_SIGNAL)) {
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        if (!dbus_message_has_path(msg, ACTIVATOR_TARGET)) {
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        /* try activating the service, don't expect reply */
        manager_activate_service::invoke(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    };

    if (!dbus_connection_add_filter(conn, filter_cb, nullptr, nullptr)) {
        errx(1, "failed to register dbus filter");
    }

    DBusObjectPathVTable vt;
    vt.message_function = [](
        DBusConnection *conn, DBusMessage *msg, void *
    ) {
        if (strcmp(dbus_message_get_interface(msg), BUS_IFACE)) {
            /* we only support our own interface at the moment */
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

        /* method or signal name */
        auto *memb = dbus_message_get_member(msg);

        switch (dbus_message_get_type(msg)) {
            case DBUS_MESSAGE_TYPE_METHOD_CALL:
                manager_method_call(conn, msg, memb);
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
        conn, BUS_OBJ, &vt, nullptr, &dbus_err
    )) {
        errx(
            1, "dbus_connection_try_register_object_path failed (%s)",
            dbus_err.message
        );
    }

    int ret = 0;

    /* run the main loop; simplify out-of-memory scenarios */
    try {
        dbus_main(conn);
    } catch (std::bad_alloc const &) {
        ret = ENOMEM;
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

    if (ret) {
        errno = ret;
        err(1, "dbus_main");
    }
    return 0;
}
