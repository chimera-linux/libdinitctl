/* libdinitctl: high level API to dinitctl socket interface
*
* Copyright 2023 q66 <q66@chimera-linux.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

#include "common.h"
#include "messages.h"

static char *reserve_sendbuf(dinitctl_t *ctl, size_t len, bool inc_size) {
    char *ret;
    if (ctl->write_cap < len) {
        size_t tlen = (ctl->write_size + ctl->write_cap);
        while (len > (tlen - ctl->write_size)) {
            /* keep doubling until we reach sufficient capacity */
            tlen *= 2;
        }
        void *np = realloc(ctl->write_buf, tlen);
        if (!np) {
            return NULL;
        }
        ctl->write_buf = np;
        ctl->write_cap = (tlen - ctl->write_size);
    }
    ret = (ctl->write_buf + ctl->write_size);
    if (inc_size) {
        ctl->write_size += len;
    }
    return ret;
}

static void consume_recvbuf(dinitctl_t *ctl, size_t len) {
    if (!len) {
        return;
    }
    ctl->read_size -= len;
    ctl->read_cap += len;
    memmove(
        ctl->read_buf,
        ctl->read_buf + len,
        ctl->read_size
    );
}

static void update_recvbuf(dinitctl_t *ctl, char *nbuf) {
    consume_recvbuf(ctl, (nbuf - ctl->read_buf));
}

static int consume_error(dinitctl_t *ctl, int err) {
    consume_recvbuf(ctl, 1);
    return err;
}

static struct dinitctl_op *new_op(dinitctl_t *ctl) {
    struct dinitctl_op *ret;
    if (ctl->op_avail) {
        ret = ctl->op_avail;
        ctl->op_avail = ret->next;
    } else {
        ret = malloc(sizeof(struct dinitctl_op));
    }
    ret->next = NULL;
    return ret;
}

static void queue_op(dinitctl_t *ctl, struct dinitctl_op *op) {
    if (!ctl->op_last) {
        /* first to queue */
        assert(!ctl->op_queue);
        ctl->op_queue = op;
    } else {
        ctl->op_last->next = op;
    }
    ctl->op_last = op;
}

DINITCTL_API int dinitctl_dispatch(dinitctl_t *ctl, int timeout, bool *ops_left) {
    struct pollfd pfd;
    ssize_t ss;
    size_t uss, read;
    int pret, ops;
    bool closed = false;
    /* preliminary */
    if (ops_left) {
        *ops_left = !!ctl->op_queue;
    }
    /* protocol error somewhere */
    if (ctl->errnov) {
        errno = ctl->errnov;
        return -1;
    }
    /* first bleed the write buffer, without blocking */
    while (ctl->write_size) {
        ss = send(ctl->fd, ctl->write_buf, ctl->write_size, 0);
        if (!ss) {
            /* exhausted buffer? should never return 0 anyway */
            break;
        }
        if (ss < 0) {
            if (errno == EINTR) {
                /* interrupted by signal, try again */
                continue;
            }
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                /* exhausted the buffer for now */
                break;
            }
            return -1;
        }
        uss = (size_t)ss;
        if (uss < ctl->write_size) {
            memmove(
                ctl->write_buf,
                ctl->write_buf + uss,
                ctl->write_size - uss
            );
        }
        ctl->write_cap += uss;
        ctl->write_size -= uss;
    }
    /* no events queued, prevent getting stuck forever */
    if (!ctl->op_queue) {
        return 0;
    }
    pfd.fd = ctl->fd;
    pfd.events = POLLIN | POLLHUP;
    pfd.revents = 0;
    pret = poll(&pfd, 1, timeout);
    if (pret < 0) {
        /* EINTR is okay though, so users should check it and re-dispatch */
        return -1;
    } else if (pret == 0) {
        return 0;
    }
    if (pfd.revents & POLLHUP) {
        /* closed by the remote side, this is not recoverable */
        closed = true;
        /* we may still be able to process something */
        if (!(pfd.revents & POLLIN)) {
            errno = EPIPE;
            return -1;
        }
    }
    /* we have data for read */
    read = 0;
    for (;;) {
        ss = recv(ctl->fd, ctl->read_buf + ctl->read_size, ctl->read_cap, 0);
        if (ss < 0) {
            if (errno == EINTR) {
                continue;
            }
            /* done reading */
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                if (!read) {
                    return 0;
                }
                /* we have data */
                break;
            }
        } else if (ss == 0) {
            /* closed by remote side, not recoverable */
            closed = true;
            if (!read) {
                errno = EPIPE;
                return -1;
            } else {
                /* process what we have before failing */
                break;
            }
        }
        uss = (size_t)ss;
        read += uss;
        ctl->read_cap -= uss;
        ctl->read_size += uss;
        if (!ctl->read_cap) {
            /* out of space: double the buffer */
            void *np = realloc(ctl->read_buf, ctl->read_size * 2);
            if (!np) {
                /* out of memory */
                return -1;
            }
            ctl->read_buf = np;
            ctl->read_cap = ctl->read_size;
        }
    }
    /* we have definitely read some bytes, try processing */
    ops = 0;
    while (ctl->op_queue) {
        struct dinitctl_op *op = ctl->op_queue;
        /* discard information packet if present */
        if (ctl->read_buf[0] >= 100) {
            if (
                (ctl->read_size <= 1) ||
                ((size_t)ctl->read_buf[1] > ctl->read_size)
            ) {
                /* broken message */
                errno = EBADMSG;
                return -1;
            }
            consume_recvbuf(ctl, ctl->read_buf[1]);
        }
        int chk = op->check_cb(ctl);
        if (chk < 0) {
            /* error */
            return chk;
        }
        if (chk > 0) {
            /* pending */
            if (closed) {
                errno = EPIPE;
                return -1;
            }
            return ops;
        }
        /* good */
        op->do_cb(ctl, op->do_data);
        if (ctl->errnov) {
            errno = ctl->errnov;
            return -1;
        }
        ++ops;
        /* move on to next operation */
        ctl->op_queue = op->next;
        /* are we last? if so, drop that too */
        if (op == ctl->op_last) {
            ctl->op_last = NULL;
        }
        /* free up the operation for reuse */
        op->next = ctl->op_avail;
        ctl->op_avail = op;
    }
    if (ops_left) {
        *ops_left = false;
    }
    if (closed) {
        errno = EPIPE;
        return -1;
    }
    return ops;
}

static bool bleed_queue(dinitctl_t *ctl) {
    bool ops_left;
    for (;;) {
        int d = dinitctl_dispatch(ctl, -1, &ops_left);
        if (d < 0) {
            if (errno == EINTR) {
                continue;
            }
            continue;
        }
        if (!ops_left) {
            return true;
        }
    }
    return false;
}

DINITCTL_API dinitctl_t *dinitctl_open(char const *socket_path) {
    struct sockaddr_un saddr;
    size_t slen = strlen(socket_path);
    int fd;

    if (slen >= sizeof(saddr.sun_path)) {
        errno = EINVAL;
        return NULL;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return NULL;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    memcpy(saddr.sun_path, socket_path, slen);

    if (connect(fd, (struct sockaddr const *)&saddr, sizeof(saddr)) < 0) {
        return NULL;
    }

    return dinitctl_open_fd(fd);
}

static int version_check(dinitctl_t *ctl) {
    if (ctl->read_size < 1) {
        return 1;
    }
    if (ctl->read_buf[0] == DINIT_RP_CPVERSION) {
        if (ctl->read_size < (2 * sizeof(uint16_t) + 1)) {
            return 1;
        }
    }
    return 0;
}

static void version_cb(dinitctl_t *ctl, void *data) {
    int *ret = data;
    uint16_t min_compat;
    uint16_t cp_ver;

    if (ctl->read_buf[0] != DINIT_RP_CPVERSION) {
        errno = ctl->errnov = EBADMSG;
        *ret = -1;
        return;
    }
    memcpy(&min_compat, &ctl->read_buf[1], sizeof(min_compat));
    memcpy(&cp_ver, &ctl->read_buf[1 + sizeof(min_compat)], sizeof(cp_ver));

    /* this library is made with protocol v2 in mind */
    if ((cp_ver < 2) || (min_compat > 2)) {
        errno = ctl->errnov = ENOTSUP;
        *ret = -1;
        return;
    }
    consume_recvbuf(ctl, 2 * sizeof(uint16_t) + 1);

    *ret = 0;
}

DINITCTL_API dinitctl_t *dinitctl_open_fd(int fd) {
    dinitctl_t *ctl;
    struct dinitctl_op *qop;
    int cvret, flags;

    if (!fd) {
        errno = EBADF;
        return NULL;
    }
    if (fcntl(fd, F_GETFD) < 0) {
        return NULL;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return NULL;
    }
    if (!(flags & O_NONBLOCK)) {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            return NULL;
        }
    }
    ctl = malloc(sizeof(dinitctl_t));
    if (!ctl) {
        return NULL;
    }
    ctl->fd = fd;
    ctl->errnov = 0;
    /* processing buffers */
    ctl->read_buf = malloc(CTLBUF_SIZE);
    if (!ctl->read_buf) {
        free(ctl);
        return NULL;
    }
    ctl->write_buf = malloc(CTLBUF_SIZE);
    if (!ctl->write_buf) {
        free(ctl->read_buf);
        free(ctl);
        return NULL;
    }
    ctl->read_size = ctl->write_size = 0;
    ctl->read_cap = ctl->write_cap = CTLBUF_SIZE;
    /* erase remaining fields */
    ctl->op_queue = ctl->op_last = ctl->op_avail = NULL;

     /* before readying, query version */
    qop = new_op(ctl);
    if (!qop) {
        int err = errno;
        dinitctl_close(ctl);
        errno = err;
        return NULL;
    }
    *reserve_sendbuf(ctl, 1, true) = DINIT_CP_QUERYVERSION;

    qop->check_cb = &version_check;
    qop->do_cb = &version_cb;
    qop->do_data = &cvret;

    queue_op(ctl, qop);

    if (!bleed_queue(ctl) || cvret) {
        int err = errno;
        dinitctl_close(ctl);
        errno = err;
        return NULL;
    }

    return ctl;
}

DINITCTL_API void dinitctl_close(dinitctl_t *ctl) {
    close(ctl->fd);
    free(ctl->read_buf);
    free(ctl->write_buf);
    free(ctl);
}

DINITCTL_API int dinitctl_get_fd(dinitctl_t *ctl) {
    return ctl->fd;
}

struct load_service_ret {
    dinitctl_service_handle_t *handle;
    int *state;
    int *target_state;
    int code;
};

static void load_service_cb(dinitctl_t *ctl, void *data) {
    struct load_service_ret *ret = data;
    ret->code = dinitctl_load_service_finish(
        ctl, ret->handle, ret->state, ret->target_state
    );
}

DINITCTL_API int dinitctl_load_service(
    dinitctl_t *ctl,
    char const *srv_name,
    bool find_only,
    dinitctl_service_handle_t *handle,
    int *state,
    int *target_state
) {
    struct load_service_ret ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    ret.handle = handle;
    ret.state = state;
    ret.target_state = target_state;
    if (dinitctl_load_service_async(
        ctl, srv_name, find_only, &load_service_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret.code;
}

static int load_service_check(dinitctl_t *ctl) {
    if (ctl->read_size < 1) {
        return 1;
    }
    if (ctl->read_buf[0] == DINIT_RP_SERVICERECORD) {
        if (ctl->read_size < (sizeof(dinitctl_service_handle_t) + 3)) {
            return 1;
        }
    }
    return 0;
}

DINITCTL_API int dinitctl_load_service_async(
    dinitctl_t *ctl,
    char const *srv_name,
    bool find_only,
    dinitctl_async_cb cb,
    void *data
) {
    size_t slen = strlen(srv_name);
    char *buf;
    uint16_t ulen;
    struct dinitctl_op *qop;

    if (slen > 1021) {
        errno = EINVAL;
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    ulen = (uint16_t)slen;
    buf = reserve_sendbuf(ctl, slen + 3, true);
    if (!buf) {
        return -1;
    }

    buf[0] = find_only ? DINIT_CP_FINDSERVICE : DINIT_CP_LOADSERVICE;
    memcpy(&buf[1], &ulen, sizeof(ulen));
    memcpy(&buf[3], srv_name, slen);

    qop->check_cb = &load_service_check;
    qop->do_cb = cb;
    qop->do_data = data;
    qop->finish_data = (void *)(uintptr_t)buf[0];

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_load_service_finish(
    dinitctl_t *ctl,
    dinitctl_service_handle_t *handle,
    int *state,
    int *target_state
) {
    char *buf;
    struct dinitctl_op *op = ctl->op_queue;
    char msg = (char)(uintptr_t)op->finish_data;

    switch (ctl->read_buf[0]) {
        case DINIT_RP_NOSERVICE:
            return consume_error(ctl, DINITCTL_ERROR_SERVICE_MISSING);
        case DINIT_RP_SERVICE_DESC_ERR:
            if (msg == DINIT_CP_FINDSERVICE) {
                goto default_err;
            }
            return consume_error(ctl, DINITCTL_ERROR_SERVICE_DESC);
        case DINIT_RP_SERVICE_LOAD_ERR:
            if (msg == DINIT_CP_FINDSERVICE) {
                goto default_err;
            }
            return consume_error(ctl, DINITCTL_ERROR_SERVICE_LOAD);
        case DINIT_RP_OOM:
            errno = ctl->errnov = ENOMEM;
            return -1;
        case DINIT_RP_SERVICERECORD:
            break;
        default_err:
        default:
            errno = ctl->errnov = EBADMSG;
            return -1;
    }

    /* service record */
    buf = ctl->read_buf + 1;

    if (state) {
        *state = *buf;
    }
    ++buf;

    memcpy(handle, buf, sizeof(*handle));
    buf += sizeof(*handle);

    if (target_state) {
        *target_state = *buf;
    }
    ++buf;

    update_recvbuf(ctl, buf);

    return DINITCTL_SUCCESS;
}

struct get_service_status_ret {
    pid_t *pid;
    int *state;
    int *target_state;
    int *flags;
    int *stop_reason;
    int *exec_stage;
    int *exit_status;
    int code;
};

static void get_service_status_cb(dinitctl_t *ctl, void *data) {
    struct get_service_status_ret *ret = data;
    ret->code = dinitctl_get_service_status_finish(
        ctl, ret->state, ret->target_state, ret->pid, ret->flags,
        ret->stop_reason, ret->exec_stage, ret->exit_status
    );
}

DINITCTL_API int dinitctl_get_service_status(
    dinitctl_t *ctl,
    dinitctl_service_handle_t handle,
    int *state,
    int *target_state,
    pid_t *pid,
    int *flags,
    int *stop_reason,
    int *exec_stage,
    int *exit_status
) {
    struct get_service_status_ret ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    ret.state = state;
    ret.target_state = target_state;
    ret.pid = pid;
    ret.flags = flags;
    ret.stop_reason = stop_reason;
    ret.exec_stage = exec_stage;
    ret.exit_status = exit_status;
    if (dinitctl_get_service_status_async(
        ctl, handle, &get_service_status_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret.code;
}

static inline size_t service_status_buffer_size(void) {
    size_t bsize = 8;
    if (sizeof(pid_t) > sizeof(int)) {
        bsize += sizeof(pid_t);
    } else {
        bsize += sizeof(int);
    }
    return bsize;
}

static int get_service_status_check(dinitctl_t *ctl) {
    if (ctl->read_size < 1) {
        return 1;
    }
    if (ctl->read_buf[0] == DINIT_RP_SERVICESTATUS) {
        return (ctl->read_size < service_status_buffer_size());
    }
    return 0;
}

DINITCTL_API int dinitctl_get_service_status_async(
    dinitctl_t *ctl,
    dinitctl_service_handle_t handle,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, sizeof(handle) + 1, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_SERVICESTATUS;
    memcpy(&buf[1], &handle, sizeof(handle));

    qop->check_cb = &get_service_status_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_get_service_status_finish(
    dinitctl_t *ctl,
    int *state,
    int *target_state,
    pid_t *pid,
    int *flags,
    int *stop_reason,
    int *exec_stage,
    int *exit_status
) {
    char *buf;
    int sreason, flgs;
    uint16_t stage;

    switch (ctl->read_buf[0]) {
        case DINIT_RP_NAK:
            return consume_error(ctl, DINITCTL_ERROR);
        case DINIT_RP_OOM:
            errno = ctl->errnov = ENOMEM;
            return -1;
        case DINIT_RP_SERVICESTATUS:
            break;
        default:
            errno = ctl->errnov = EBADMSG;
            return -1;
    }

    /* now extract the status */
    buf = ctl->read_buf + 2;

    if (state) {
        *state = *buf;
    }
    ++buf;
    if (target_state) {
        *target_state = *buf;
    }
    ++buf;

    flgs = *buf++;
    if (flags) {
        *flags = flgs;
    }
    sreason = *buf++;
    if (stop_reason) {
        *stop_reason = sreason;
    }

    /* only under specific circumstances but we have to read it anyway */
    memcpy(&stage, buf, sizeof(stage));
    buf += sizeof(stage);

    if (flgs & DINITCTL_SERVICE_FLAG_HAS_PID) {
        if (pid) {
            memcpy(pid, buf, sizeof(*pid));
        }
    } else {
        if (sreason == DINITCTL_SERVICE_STOP_REASON_EXEC_FAILED) {
            if (exec_stage) {
                *exec_stage = stage;
            }
        }
        if (exit_status) {
            memcpy(exit_status, buf, sizeof(*exit_status));
        }
    }

    consume_recvbuf(ctl, service_status_buffer_size());
    return DINITCTL_SUCCESS;
}

static void setenv_cb(dinitctl_t *ctl, void *data) {
    *((int *)data) = dinitctl_setenv_finish(ctl);
}

DINITCTL_API int dinitctl_setenv(dinitctl_t *ctl, char const *env_var) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_setenv_async(ctl, env_var, &setenv_cb, &ret) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int setenv_check(dinitctl_t *ctl) {
    return (ctl->read_size < 1);
}

DINITCTL_API int dinitctl_setenv_async(
    dinitctl_t *ctl, char const *env_var, dinitctl_async_cb cb, void *data
) {
    char *buf;
    struct dinitctl_op *qop;
    size_t varlen = strlen(env_var);
    uint16_t vlen;

    if (!varlen || (varlen > 1021)) {
        errno = EINVAL;
        return -1;
    }
    vlen = (uint16_t)varlen;

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, varlen + sizeof(uint16_t) + 1, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_SETENV;
    memcpy(&buf[1], &vlen, sizeof(vlen));
    memcpy(&buf[1 + sizeof(vlen)], env_var, vlen);

    qop->check_cb = &setenv_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_setenv_finish(dinitctl_t *ctl) {
    char c = ctl->read_buf[0];
    consume_recvbuf(ctl, 1);

    if (c == DINIT_RP_ACK) {
        return DINITCTL_SUCCESS;
    } else if (c == DINIT_RP_BADREQ) {
        return DINITCTL_ERROR;
    }

    errno = ctl->errnov = EBADMSG;
    return -1;
}

#if 0

TODO:

/* Start or stop a service */
#define DINIT_CP_STARTSERVICE 3
#define DINIT_CP_STOPSERVICE  4
#define DINIT_CP_WAKESERVICE 5
#define DINIT_CP_RELEASESERVICE 6

#define DINIT_CP_UNPINSERVICE 7

/* List services */
#define DINIT_CP_LISTSERVICES 8

/* Unload a service */
#define DINIT_CP_UNLOADSERVICE 9

/* Shutdown */
#define DINIT_CP_SHUTDOWN 10
 /* followed by 1-byte shutdown type */

/* Add/remove dependency to existing service */
#define DINIT_CP_ADD_DEP 11
#define DINIT_CP_REM_DEP 12

/* Query service load path / mechanism */
#define DINIT_CP_QUERY_LOAD_MECH 13

/* Add a waits for dependency from one service to another, and start the dependency */
#define DINIT_CP_ENABLESERVICE 14

/* Find the name of a service (from a handle) */
#define DINIT_CP_QUERYSERVICENAME 15

/* Reload a service */
#define DINIT_CP_RELOADSERVICE 16

/* Query status of an individual service */
#define DINIT_CP_SERVICESTATUS 18

/* Set trigger value for triggered services */
#define DINIT_CP_SETTRIGGER 19

/* Retrieve buffered output */
#define DINIT_CP_CATLOG 20

/* Send Signal to process */
#define DINIT_CP_SIGNAL 21

#endif
