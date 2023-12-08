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
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <pwd.h>

#include "config.h"

#include "common.h"
#include "messages.h"

/* handle cache map */

static dinitctl_service_handle *handle_find(dinitctl *ctl, uint32_t key) {
    dinitctl_service_handle *hptr = ctl->hndl_map[key % HANDLE_BUCKETN];
    while (hptr && hptr->idx != key) {
        hptr = hptr->next;
    }
    return hptr;
}

static bool handle_verify(dinitctl *ctl, dinitctl_service_handle *hndl) {
    if (!hndl || (handle_find(ctl, hndl->idx) != hndl)) {
        errno = EINVAL;
        return false;
    }
    return true;
}

/* must not already exist */
static dinitctl_service_handle *handle_add(dinitctl *ctl, uint32_t key) {
    dinitctl_service_handle *hptr;
    if (!ctl->hndl_unused) {
        /* allocate a new chunk */
        struct dinitctl_handle_chunk *chnk = malloc(
            sizeof(struct dinitctl_handle_chunk)
        );
        if (!chnk) {
            return NULL;
        }
        chnk->next = ctl->hndl_chunk;
        /* link up the free handles */
        for (size_t i = 0; i < (HANDLE_CHUNKN - 1); ++i) {
            chnk->data[i].idx = UINT32_MAX;
            chnk->data[i].next = &chnk->data[i + 1];
        }
        chnk->data[HANDLE_CHUNKN - 1].idx = UINT32_MAX;
        chnk->data[HANDLE_CHUNKN - 1].next = NULL;
        ctl->hndl_unused = chnk->data;
        ctl->hndl_chunk = chnk;
    }
    hptr = ctl->hndl_unused;
    ctl->hndl_unused = hptr->next;
    hptr->idx = key;
    hptr->next = ctl->hndl_map[key % HANDLE_BUCKETN];
    ctl->hndl_map[key % HANDLE_BUCKETN] = hptr;
    return hptr;
}

static int handle_reg(dinitctl *ctl, dinitctl_service_handle **out, char *buf) {
    uint32_t v;
    memcpy(&v, buf, sizeof(v));
    if (!(*out = handle_add(ctl, v))) {
        return -1;
    }
    return 0;
}

static int handle_check(dinitctl *ctl, char *buf) {
    uint32_t v;
    memcpy(&v, buf, sizeof(v));
    if (!handle_find(ctl, v)) {
        return -1;
    }
    return 0;
}

/* assumes existence has been verified already */
static void handle_del(dinitctl *ctl, uint32_t key) {
    dinitctl_service_handle *hptr = ctl->hndl_map[key % HANDLE_BUCKETN];
    dinitctl_service_handle *hprev = NULL;
    while (hptr) {
        if (hptr->idx == key) {
            if (hprev) {
                hprev->next = hptr->next;
            } else {
                ctl->hndl_map[key % HANDLE_BUCKETN] = hptr->next;
            }
            hptr->idx = UINT32_MAX;
            hptr->next = ctl->hndl_unused;
            ctl->hndl_unused = hptr;
            break;
        }
        hprev = hptr;
        hptr = hptr->next;
    }
}

/* buffer management */

static char *reserve_sendbuf(dinitctl *ctl, size_t len, bool inc_size) {
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

static void consume_recvbuf(dinitctl *ctl, size_t len) {
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

static void update_recvbuf(dinitctl *ctl, char *nbuf) {
    consume_recvbuf(ctl, (nbuf - ctl->read_buf));
}

static int consume_enum(dinitctl *ctl, int val) {
    consume_recvbuf(ctl, 1);
    return val;
}

static struct dinitctl_op *new_op(dinitctl *ctl) {
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

static void queue_op(dinitctl *ctl, struct dinitctl_op *op) {
    if (!ctl->op_last) {
        /* first to queue */
        assert(!ctl->op_queue);
        ctl->op_queue = op;
    } else {
        ctl->op_last->next = op;
    }
    ctl->op_last = op;
}

static inline size_t status_buffer_size(void) {
    size_t bsize = 6;
    if (sizeof(pid_t) > sizeof(int)) {
        bsize += sizeof(pid_t);
    } else {
        bsize += sizeof(int);
    }
    return bsize;
}

static void fill_status(
    char *buf,
    dinitctl_service_status *sbuf
) {
    uint16_t stage;

    sbuf->state = *buf++;
    sbuf->target_state = *buf++;
    sbuf->flags = *buf++;
    sbuf->stop_reason = *buf++;
    /* default other fields */
    sbuf->exec_stage = 0;
    sbuf->exit_status = 0;
    sbuf->pid = 0;

    /* only under specific circumstances but we have to read it anyway */
    memcpy(&stage, buf, sizeof(stage));
    buf += sizeof(stage);

    if (sbuf->flags & DINITCTL_SERVICE_FLAG_HAS_PID) {
        memcpy(&sbuf->pid, buf, sizeof(sbuf->pid));
    } else {
        if (sbuf->stop_reason == DINITCTL_SERVICE_STOP_REASON_EXEC_FAILED) {
            sbuf->exec_stage = stage;
        }
        memcpy(&sbuf->exit_status, buf, sizeof(sbuf->exit_status));
    }
}

static int event_check(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_IP_SERVICEEVENT) {
        size_t reqsz = status_buffer_size() + sizeof(uint32_t) + 2;
        char psz = ctl->read_buf[1];
        /* ensure the packet will provide enough data */
        if (psz < (int)reqsz) {
            return -1;
        }
        /* wait until we've gotten the handle */
        if (ctl->read_size < (sizeof(uint32_t) + 2)) {
            return 1;
        }
        if (handle_check(ctl, &ctl->read_buf[2]) < 0) {
            return -1;
        }
        /* wait for full packet */
        return (ctl->read_size < (size_t)psz);
    }
    return -1;
}

static void event_cb(dinitctl *ctl, void *data) {
    (void)data;
    if (ctl->sv_event_cb) {
        char *buf = &ctl->read_buf[2];
        uint32_t handle;
        dinitctl_service_status sbuf;
        int sv_event;
        memcpy(&handle, buf, sizeof(handle));
        buf += sizeof(handle);
        sv_event = *buf++;
        fill_status(buf, &sbuf);
        ctl->sv_event_cb(
            ctl, handle_find(ctl, handle), sv_event, &sbuf, ctl->sv_event_data
        );
    }
    consume_recvbuf(ctl, ctl->read_buf[1]);
}

DINITCTL_API int dinitctl_dispatch(dinitctl *ctl, int timeout, bool *ops_left) {
    struct pollfd pfd;
    ssize_t ss;
    size_t uss, read;
    int pret, ops;
    bool closed = false;
    /* preliminary */
    if (ops_left) {
        *ops_left = !!ctl->op_queue;
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
    /* polling on -1 would do potentially infinite poll */
    if (ctl->fd < 0) {
        errno = EPIPE;
        return -1;
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
        /* process service events; this involves queuing an event ahead
         * of everything else so it's processed with the data bytes
         */
        if ((ctl->read_buf[0] >= 100) && (op->check_cb != &event_check)) {
            struct dinitctl_op *nop = new_op(ctl);
            if (!nop) {
                return -1;
            }
            nop->check_cb = &event_check;
            nop->do_cb = &event_cb;
            nop->do_data = NULL;
            nop->next = op;
            op = ctl->op_queue = nop;
        }
        if (ctl->read_buf[0] == DINIT_RP_OOM) {
            errno = ENOMEM;
            return -1;
        }
        errno = 0;
        int chk = op->check_cb(ctl);
        if (chk < 0) {
            /* error */
            if (!errno) {
                errno = EBADMSG;
            }
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

static bool bleed_queue(dinitctl *ctl) {
    bool ops_left;
    for (;;) {
        int d = dinitctl_dispatch(ctl, -1, &ops_left);
        if (d < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (!ops_left) {
            return true;
        }
    }
    return false;
}

static dinitctl *open_sock(char const *base, char const *sock) {
    struct sockaddr_un saddr;
    size_t slen = strlen(base), tlen = slen;
    int fd;

    if (sock) {
        if (base[tlen - 1] != '/') {
            tlen += 1;
        }
        tlen += strlen(sock);
    }
    if (tlen >= sizeof(saddr.sun_path)) {
        errno = EINVAL;
        return NULL;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return NULL;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    memcpy(saddr.sun_path, base, slen);
    if (tlen > slen) {
        if (saddr.sun_path[slen - 1] != '/') {
            saddr.sun_path[slen] = '/';
            memcpy(&saddr.sun_path[slen + 1], sock, tlen - slen - 1);
        } else {
            memcpy(&saddr.sun_path[slen], sock, tlen - slen);
        }
    }

    if (connect(fd, (struct sockaddr const *)&saddr, sizeof(saddr)) < 0) {
        return NULL;
    }

    return dinitctl_open_fd(fd);
}

DINITCTL_API dinitctl *dinitctl_open(char const *socket_path) {
    return open_sock(socket_path, NULL);
}

DINITCTL_API dinitctl *dinitctl_open_system(void) {
    return dinitctl_open(DINIT_CONTROL_SOCKET);
}

DINITCTL_API dinitctl *dinitctl_open_user(void) {
    char const *rdir = getenv("XDG_RUNTIME_DIR");
    char const *sock = "dinitctl";
    if (!rdir) {
        rdir = getenv("HOME");
        sock = ".dinitctl";
    }
    if (!rdir) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            rdir = pw->pw_dir;
        }
    }
    if (!rdir) {
        errno = ENOENT;
        return NULL;
    }
    return open_sock(rdir, sock);
}

DINITCTL_API dinitctl *dinitctl_open_default(void) {
    if (geteuid() == 0) {
        return dinitctl_open_system();
    }
    return dinitctl_open_user();
}

static int version_check(dinitctl *ctl) {
    uint16_t min_compat;
    uint16_t cp_ver;

    if (ctl->read_buf[0] == DINIT_RP_CPVERSION) {
        if (ctl->read_size < (2 * sizeof(uint16_t) + 1)) {
            return 1;
        }
    } else {
        return -1;
    }

    memcpy(&min_compat, &ctl->read_buf[1], sizeof(min_compat));
    memcpy(&cp_ver, &ctl->read_buf[1 + sizeof(min_compat)], sizeof(cp_ver));

    /* the remote side must be at least our protocol version, while still
     * explicitly supporting our protocol version (no API break)
     */
    if ((cp_ver < DINIT_PROTOCOLVER) || (min_compat > DINIT_PROTOCOLVER)) {
        errno = ENOTSUP;
        return -1;
    }

    return 0;
}

static void version_cb(dinitctl *ctl, void *data) {
    int *ret = data;

    consume_recvbuf(ctl, 2 * sizeof(uint16_t) + 1);

    *ret = 0;
}

DINITCTL_API dinitctl *dinitctl_open_fd(int fd) {
    dinitctl *ctl;
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
    ctl = malloc(sizeof(dinitctl));
    if (!ctl) {
        return NULL;
    }
    ctl->fd = fd;
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
    ctl->hndl_unused = NULL;
    ctl->hndl_chunk = NULL;
    ctl->op_queue = ctl->op_last = ctl->op_avail = NULL;
    ctl->sv_event_cb = NULL;
    ctl->sv_event_data = NULL;
    for (size_t i = 0; i < (sizeof(ctl->hndl_map) / sizeof(void *)); ++i) {
        ctl->hndl_map[i] = NULL;
    }

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
        /* make sure we don't get stuck polling */
        close(ctl->fd);
        ctl->fd = -1;
        dinitctl_close(ctl);
        errno = err;
        return NULL;
    }

    return ctl;
}

DINITCTL_API void dinitctl_close(dinitctl *ctl) {
    /* finish processing what we can */
    bleed_queue(ctl);
    /* then close the associated stuff */
    close(ctl->fd);
    free(ctl->read_buf);
    free(ctl->write_buf);
    /* free handle management stuff */
    while (ctl->hndl_chunk) {
        struct dinitctl_handle_chunk *next = ctl->hndl_chunk->next;
        free(ctl->hndl_chunk);
        ctl->hndl_chunk = next;
    }
    /* free any remaining allocated ops */
    while (ctl->op_avail) {
        struct dinitctl_op *next = ctl->op_avail->next;
        free(ctl->op_avail);
        ctl->op_avail = next;
    }
    while (ctl->op_queue) {
        struct dinitctl_op *next = ctl->op_queue->next;
        free(ctl->op_queue);
        ctl->op_queue = next;
    }
    free(ctl);
}

DINITCTL_API int dinitctl_get_fd(dinitctl *ctl) {
    return ctl->fd;
}

DINITCTL_API void dinitctl_set_service_event_callback(
    dinitctl *ctl, dinitctl_service_event_cb cb, void *data
) {
    ctl->sv_event_cb = cb;
    ctl->sv_event_data = data;
}

struct load_service_ret {
    dinitctl_service_handle **handle;
    enum dinitctl_service_state *state;
    enum dinitctl_service_state *target_state;
    int code;
};

static void load_service_cb(dinitctl *ctl, void *data) {
    struct load_service_ret *ret = data;
    ret->code = dinitctl_load_service_finish(
        ctl, ret->handle, ret->state, ret->target_state
    );
}

DINITCTL_API int dinitctl_load_service(
    dinitctl *ctl,
    char const *srv_name,
    bool find_only,
    dinitctl_service_handle **handle,
    enum dinitctl_service_state *state,
    enum dinitctl_service_state *target_state
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

static int load_service_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_SERVICERECORD:
            if (ctl->read_size < (sizeof(uint32_t) + 3)) {
                return 1;
            }
            /* ensure the handle is not already present */
            if (!handle_check(ctl, &ctl->read_buf[2])) {
                return -1;
            }
            return 0;
        case DINIT_RP_NOSERVICE:
            return 0;
        case DINIT_RP_SERVICE_DESC_ERR:
        case DINIT_RP_SERVICE_LOAD_ERR:
            if (ctl->op_queue->flag) {
                return -1;
            }
            return 0;
        default:
            break;
    }
    return -1;
}

DINITCTL_API int dinitctl_load_service_async(
    dinitctl *ctl,
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
    qop->flag = find_only;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_load_service_finish(
    dinitctl *ctl,
    dinitctl_service_handle **handle,
    enum dinitctl_service_state *state,
    enum dinitctl_service_state *target_state
) {
    char *buf;

    switch (ctl->read_buf[0]) {
        case DINIT_RP_NOSERVICE:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_MISSING);
        case DINIT_RP_SERVICE_DESC_ERR:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_DESC);
        case DINIT_RP_SERVICE_LOAD_ERR:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_LOAD);
        default:
            break;
    }

    /* service record */
    buf = ctl->read_buf + 1;

    if (state) {
        *state = *buf;
    }
    ++buf;

    if (handle_reg(ctl, handle, buf) < 0) {
        update_recvbuf(ctl, buf + sizeof(uint32_t) + 1);
        errno = ENOMEM;
        return -1;
    }
    buf += sizeof(uint32_t);

    if (target_state) {
        *target_state = *buf;
    }
    ++buf;

    update_recvbuf(ctl, buf);

    return DINITCTL_SUCCESS;
}

static void unload_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_unload_service_finish(ctl);
}

DINITCTL_API int dinitctl_unload_service(
    dinitctl *ctl, dinitctl_service_handle *handle, bool reload
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_unload_service_async(
        ctl, handle, reload, &unload_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int unload_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_NAK:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_unload_service_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    bool reload,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 1 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = reload ? DINIT_CP_RELOADSERVICE : DINIT_CP_UNLOADSERVICE;
    memcpy(&buf[1], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &unload_check;
    qop->do_cb = cb;
    qop->do_data = data;
    qop->handle = handle;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_unload_service_finish(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_RP_NAK) {
        return consume_enum(ctl, DINITCTL_ERROR);
    }
    /* unregister handle on success */
    handle_del(ctl, ctl->op_queue->handle->idx);
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void close_handle_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_close_service_handle_finish(ctl);
}

DINITCTL_API int dinitctl_close_service_handle(
    dinitctl *ctl, dinitctl_service_handle *handle
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_close_service_handle_async(
        ctl, handle, &close_handle_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int close_handle_check(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_RP_ACK) {
        return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_close_service_handle_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 1 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_CLOSEHANDLE;
    memcpy(&buf[1], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &close_handle_check;
    qop->do_cb = cb;
    qop->do_data = data;
    qop->handle = handle;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_close_service_handle_finish(dinitctl *ctl) {
    /* unregister handle on success */
    handle_del(ctl, ctl->op_queue->handle->idx);
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void start_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_start_service_finish(ctl);
}

DINITCTL_API int dinitctl_start_service(
    dinitctl *ctl, dinitctl_service_handle *handle, bool pin
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_start_service_async(
        ctl, handle, pin, &start_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int start_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_SHUTTINGDOWN:
        case DINIT_RP_PINNEDSTOPPED:
        case DINIT_RP_ALREADYSS:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_start_service_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    bool pin,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 2 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_STARTSERVICE;
    buf[1] = pin ? 1 : 0;
    memcpy(&buf[2], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &start_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_start_service_finish(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_SHUTTINGDOWN:
            return consume_enum(ctl, DINITCTL_ERROR_SHUTTING_DOWN);
        case DINIT_RP_PINNEDSTOPPED:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_PINNED);
        case DINIT_RP_ALREADYSS:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_ALREADY);
        default:
            break;
    }
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void stop_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_stop_service_finish(ctl);
}

DINITCTL_API int dinitctl_stop_service(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    bool pin,
    bool restart,
    bool gentle
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_stop_service_async(
        ctl, handle, pin, restart, gentle, &stop_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int stop_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_SHUTTINGDOWN:
        case DINIT_RP_PINNEDSTARTED:
        case DINIT_RP_ALREADYSS:
        case DINIT_RP_NAK:
            return 0;
        case DINIT_RP_DEPENDENTS:
            if (ctl->op_queue->flag) {
                return 0;
            }
            break;
    }
    return -1;
}

DINITCTL_API int dinitctl_stop_service_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    bool pin,
    bool restart,
    bool gentle,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 2 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_STOPSERVICE;
    buf[1] = pin ? 1 : 0;
    if (gentle) {
        buf[1] |= (1 << 1);
    }
    if (restart) {
        buf[1] |= (1 << 2);
    }
    memcpy(&buf[2], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &stop_check;
    qop->do_cb = cb;
    qop->do_data = data;
    qop->flag = gentle;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_stop_service_finish(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_SHUTTINGDOWN:
            return consume_enum(ctl, DINITCTL_ERROR_SHUTTING_DOWN);
        case DINIT_RP_PINNEDSTARTED:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_PINNED);
        case DINIT_RP_ALREADYSS:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_ALREADY);
        case DINIT_RP_DEPENDENTS:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_DEPENDENTS);
        case DINIT_RP_NAK:
            return consume_enum(ctl, DINITCTL_ERROR);
        default:
            break;
    }
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void wake_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_wake_service_finish(ctl);
}

DINITCTL_API int dinitctl_wake_service(
    dinitctl *ctl, dinitctl_service_handle *handle, bool pin
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_wake_service_async(
        ctl, handle, pin, &wake_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int wake_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_SHUTTINGDOWN:
        case DINIT_RP_PINNEDSTOPPED:
        case DINIT_RP_ALREADYSS:
        case DINIT_RP_NAK:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_wake_service_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    bool pin,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 2 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_WAKESERVICE;
    buf[1] = pin ? 1 : 0;
    memcpy(&buf[2], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &wake_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_wake_service_finish(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_SHUTTINGDOWN:
            return consume_enum(ctl, DINITCTL_ERROR_SHUTTING_DOWN);
        case DINIT_RP_PINNEDSTOPPED:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_PINNED);
        case DINIT_RP_ALREADYSS:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_ALREADY);
        case DINIT_RP_NAK:
            return consume_enum(ctl, DINITCTL_ERROR);
        default:
            break;
    }
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void release_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_release_service_finish(ctl);
}

DINITCTL_API int dinitctl_release_service(
    dinitctl *ctl, dinitctl_service_handle *handle, bool pin
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_release_service_async(
        ctl, handle, pin, &release_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int release_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_ALREADYSS:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_release_service_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    bool pin,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 2 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_RELEASESERVICE;
    buf[1] = pin ? 1 : 0;
    memcpy(&buf[2], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &release_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_release_service_finish(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_RP_ALREADYSS) {
        return consume_enum(ctl, DINITCTL_ERROR_SERVICE_ALREADY);
    }
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void unpin_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_unpin_service_finish(ctl);
}

DINITCTL_API int dinitctl_unpin_service(
    dinitctl *ctl, dinitctl_service_handle *handle
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_unpin_service_async(ctl, handle, &unpin_cb, &ret) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int unpin_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_unpin_service_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 1 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_UNPINSERVICE;
    memcpy(&buf[2], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &unpin_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_unpin_service_finish(dinitctl *ctl) {
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

struct get_service_name_ret {
    char **out;
    ssize_t *outs;
    int code;
};

static void get_service_name_cb(dinitctl *ctl, void *data) {
    struct get_service_name_ret *ret = data;
    ret->code = dinitctl_get_service_name_finish(ctl, ret->out, ret->outs);
}

DINITCTL_API int dinitctl_get_service_name(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    char **name,
    ssize_t *buf_len
) {
    struct get_service_name_ret ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    ret.out = name;
    ret.outs = buf_len;
    if (dinitctl_get_service_name_async(
        ctl, handle, &get_service_name_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret.code;
}

static int get_service_name_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_NAK:
            return 0;
        case DINIT_RP_SERVICENAME: {
            uint16_t nlen;
            if (ctl->read_size < (sizeof(nlen) + 2)) {
                return 1;
            }
            memcpy(&nlen, &ctl->read_buf[2], sizeof(nlen));
            if (ctl->read_size < (nlen + sizeof(nlen) + 2)) {
                return 1;
            }
            return 0;
        }
        default:
            break;
    }
    return -1;
}

DINITCTL_API int dinitctl_get_service_name_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, sizeof(handle->idx) + 2, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_QUERYSERVICENAME;
    buf[1] = 0;
    memcpy(&buf[2], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &get_service_name_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_get_service_name_finish(
    dinitctl *ctl, char **name, ssize_t *buf_len
) {
    uint16_t nlen;
    size_t alen, wlen;
    int ret = DINITCTL_SUCCESS;

    if (ctl->read_buf[0] == DINIT_RP_NAK) {
        return consume_enum(ctl, DINITCTL_ERROR);
    }

    memcpy(&nlen, &ctl->read_buf[2], sizeof(nlen));
    alen = nlen;

    if (*buf_len < 0) {
        /* allocate the storage */
        *name = malloc(alen + 1);
        if (!*name) {
            ret = -1;
            goto do_ret;
        }
        wlen = alen;
    } else if (!*buf_len) {
        /* pure length query */
        *buf_len = alen;
        goto do_ret;
    } else {
        wlen = *buf_len - 1;
        if (alen < wlen) {
            wlen = alen;
        }
    }

    memcpy(*name, &ctl->read_buf[2 + sizeof(nlen)], wlen);
    /* terminate */
    *name[wlen] = '\0';
    *buf_len = alen;

do_ret:
    consume_recvbuf(ctl, nlen + sizeof(nlen) + 2);
    return ret;
}

struct get_service_log_ret {
    char **out;
    ssize_t *outs;
    int code;
};

static void get_service_log_cb(dinitctl *ctl, void *data) {
    struct get_service_log_ret *ret = data;
    ret->code = dinitctl_get_service_log_finish(ctl, ret->out, ret->outs);
}

DINITCTL_API int dinitctl_get_service_log(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    int flags,
    char **log,
    ssize_t *buf_len
) {
    struct get_service_log_ret ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    ret.out = log;
    ret.outs = buf_len;
    if (dinitctl_get_service_log_async(
        ctl, handle, flags, &get_service_log_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret.code;
}

static int get_service_log_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_NAK:
            return 0;
        case DINIT_RP_SERVICE_LOG: {
            unsigned int nlen;
            if (ctl->read_size < (sizeof(nlen) + 2)) {
                return 1;
            }
            memcpy(&nlen, &ctl->read_buf[2], sizeof(nlen));
            if (ctl->read_size < (nlen + sizeof(nlen) + 2)) {
                return 1;
            }
            return 0;
        }
        default:
            break;
    }
    return -1;
}

DINITCTL_API int dinitctl_get_service_log_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    int flags,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (flags && (flags != DINITCTL_LOG_BUFFER_CLEAR)) {
        errno = EINVAL;
        return -1;
    }

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, sizeof(handle->idx) + 2, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_CATLOG;
    buf[1] = (char)flags;
    memcpy(&buf[2], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &get_service_log_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_get_service_log_finish(
    dinitctl *ctl, char **log, ssize_t *buf_len
) {
    int ret = DINITCTL_SUCCESS;
    unsigned int nlen;
    size_t alen, wlen;

    if (ctl->read_buf[0] == DINIT_RP_NAK) {
        return consume_enum(ctl, DINITCTL_ERROR);
    }

    memcpy(&nlen, &ctl->read_buf[2], sizeof(nlen));
    alen = nlen;

    if (*buf_len < 0) {
        /* allocate the storage */
        *log = malloc(alen + 1);
        if (!*log) {
            ret = -1;
            goto do_ret;
        }
        wlen = alen;
    } else if (!*buf_len) {
        /* pure length query */
        *buf_len = alen;
        goto do_ret;
    } else {
        wlen = *buf_len - 1;
        if (alen < wlen) {
            wlen = alen;
        }
    }

    memcpy(*log, &ctl->read_buf[2 + sizeof(nlen)], wlen);
    /* terminate */
    *log[wlen] = '\0';
    *buf_len = alen;

do_ret:
    consume_recvbuf(ctl, nlen + sizeof(nlen) + 2);
    return ret;
}

struct get_service_status_ret {
    dinitctl_service_status *status;
    int code;
};

static void get_service_status_cb(dinitctl *ctl, void *data) {
    struct get_service_status_ret *ret = data;
    ret->code = dinitctl_get_service_status_finish(ctl, ret->status);
}

DINITCTL_API int dinitctl_get_service_status(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    dinitctl_service_status *status
) {
    struct get_service_status_ret ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    ret.status = status;
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

static int get_service_status_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_NAK:
            return 0;
        case DINIT_RP_SERVICESTATUS: {
            return (ctl->read_size < (status_buffer_size() + 2));
        }
        default:
            break;
    }
    return -1;
}

DINITCTL_API int dinitctl_get_service_status_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, sizeof(handle->idx) + 1, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_SERVICESTATUS;
    memcpy(&buf[1], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &get_service_status_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_get_service_status_finish(
    dinitctl *ctl,
    dinitctl_service_status *status
) {
    if (ctl->read_buf[0] == DINIT_RP_NAK) {
        return consume_enum(ctl, DINITCTL_ERROR);
    }
    fill_status(ctl->read_buf + 2, status);
    consume_recvbuf(ctl, status_buffer_size() + 2);
    return DINITCTL_SUCCESS;
}

static void add_rm_dep_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_add_remove_service_dependency_finish(ctl);
}

DINITCTL_API int dinitctl_add_remove_service_dependency(
    dinitctl *ctl,
    dinitctl_service_handle *from_handle,
    dinitctl_service_handle *to_handle,
    enum dinitctl_dependency_type type,
    bool remove,
    bool enable
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_add_remove_service_dependency_async(
        ctl, from_handle, to_handle, type, remove, enable, &add_rm_dep_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int add_rm_dep_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_NAK:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_add_remove_service_dependency_async(
    dinitctl *ctl,
    dinitctl_service_handle *from_handle,
    dinitctl_service_handle *to_handle,
    enum dinitctl_dependency_type type,
    bool remove,
    bool enable,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, from_handle) || !handle_verify(ctl, to_handle)) {
        return -1;
    }

    switch (type) {
        case DINITCTL_DEPENDENCY_REGULAR:
        case DINITCTL_DEPENDENCY_WAITS_FOR:
        case DINITCTL_DEPENDENCY_MILESTONE:
            break;
        default:
            errno = EINVAL;
            return -1;
    }
    if (enable && remove) {
        errno = EINVAL;
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 2 + 2 * sizeof(from_handle->idx), true);
    if (!buf) {
        return -1;
    }

    if (enable) {
        buf[0] = DINIT_CP_ENABLESERVICE;
    } else if (remove) {
        buf[0] = DINIT_CP_REM_DEP;
    } else {
        buf[0] = DINIT_CP_ADD_DEP;
    }
    buf[1] = (char)type;
    memcpy(&buf[2], &from_handle->idx, sizeof(from_handle->idx));
    memcpy(&buf[2 + sizeof(from_handle->idx)], &to_handle->idx, sizeof(to_handle->idx));

    qop->check_cb = &add_rm_dep_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_add_remove_service_dependency_finish(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_RP_NAK) {
        return consume_enum(ctl, DINITCTL_ERROR);
    }
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void trigger_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_set_service_trigger_finish(ctl);
}

DINITCTL_API int dinitctl_set_service_trigger(
    dinitctl *ctl, dinitctl_service_handle *handle, bool trigger
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_set_service_trigger_async(
        ctl, handle, trigger, &trigger_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int trigger_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_NAK:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_set_service_trigger_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    bool trigger,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 2 + sizeof(handle->idx), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_SETTRIGGER;
    memcpy(&buf[1], &handle->idx, sizeof(handle->idx));
    buf[1 + sizeof(handle->idx)] = (char)trigger;

    qop->check_cb = &trigger_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_set_service_trigger_finish(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_RP_NAK) {
        return consume_enum(ctl, DINITCTL_ERROR);
    }
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void signal_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_signal_service_finish(ctl);
}

DINITCTL_API int dinitctl_signal_service(
    dinitctl *ctl, dinitctl_service_handle *handle, int signum
) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_signal_service_async(
        ctl, handle, signum, &signal_cb, &ret
    ) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int signal_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_ACK:
        case DINIT_RP_NAK:
        case DINIT_RP_SIGNAL_NOPID:
        case DINIT_RP_SIGNAL_BADSIG:
        case DINIT_RP_SIGNAL_KILLERR:
            return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_signal_service_async(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    int signum,
    dinitctl_async_cb cb,
    void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    if (!handle_verify(ctl, handle)) {
        return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 1 + sizeof(handle->idx) + sizeof(signum), true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_SIGNAL;
    memcpy(&buf[1], &signum, sizeof(signum));
    memcpy(&buf[1 + sizeof(signum)], &handle->idx, sizeof(handle->idx));

    qop->check_cb = &signal_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_signal_service_finish(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_NAK:
            return consume_enum(ctl, DINITCTL_ERROR);
        case DINIT_RP_SIGNAL_NOPID:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_NO_PID);
        case DINIT_RP_SIGNAL_BADSIG:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_BAD_SIGNAL);
        case DINIT_RP_SIGNAL_KILLERR:
            return consume_enum(ctl, DINITCTL_ERROR_SERVICE_SIGNAL_FAILED);
        default:
            break;
    }
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

struct list_services_ret {
    dinitctl_service_list_entry **out;
    ssize_t *outs;
    int code;
};

static void list_services_cb(dinitctl *ctl, void *data) {
    struct list_services_ret *ret = data;
    ret->code = dinitctl_list_services_finish(ctl, ret->out, ret->outs);
}

DINITCTL_API int dinitctl_list_services(
    dinitctl *ctl, dinitctl_service_list_entry **entries, ssize_t *len
) {
    struct list_services_ret ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    ret.out = entries;
    ret.outs = len;
    if (dinitctl_list_services_async(ctl, &list_services_cb, &ret) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret.code;
}

static int list_services_check(dinitctl *ctl) {
    size_t sbufs, rsize;
    char *rbuf;
    switch (ctl->read_buf[0]) {
        case DINIT_RP_SVCINFO:
            break;
        case DINIT_RP_LISTDONE:
            return 0;
        default:
            return -1;
    }
    /* now count the entries */
    sbufs = status_buffer_size();
    rsize = ctl->read_size;
    rbuf = ctl->read_buf;
    for (;;) {
        unsigned char rnlen;
        size_t namlen;
        if (rsize < 2) {
            return 1;
        }
        memcpy(&rnlen, &rbuf[1], 1);
        /* control protocol permits up to 256, but that overflows */
        if (!rnlen) {
            namlen = 256;
        } else {
            namlen = rnlen;
        }
        /* entry (svcinfo + namlen + sbuf) + listdone/svcinfo */
        if (rsize < (3 + sbufs + namlen)) {
            return 1;
        }
        /* final entry */
        if (rbuf[sbufs + namlen + 2] == DINIT_RP_LISTDONE) {
            return 0;
        }
        /* otherwise it must be next entry, or the message is bad */
        if (rbuf[sbufs + namlen + 2] != DINIT_RP_SVCINFO) {
            break;
        }
        /* move on to next */
        rbuf += sbufs + namlen + 2;
        rsize -= sbufs + namlen + 2;
    }
    return -1;
}

DINITCTL_API int dinitctl_list_services_async(
    dinitctl *ctl, dinitctl_async_cb cb, void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 1, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_LISTSERVICES;

    qop->check_cb = &list_services_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_list_services_finish(
    dinitctl *ctl, dinitctl_service_list_entry **entries, ssize_t *len
) {
    int ret = DINITCTL_SUCCESS;
    size_t sbufs, nentries, wentries, cons = 0;
    char *buf = ctl->read_buf;
    dinitctl_service_list_entry *curentry;

    /* zero entries */
    if (buf[0] == DINIT_RP_LISTDONE) {
        *len = 0;
        consume_recvbuf(ctl, 1);
        return DINITCTL_SUCCESS;
    }

    /* otherwise count them for allocation purposes */
    sbufs = status_buffer_size();
    nentries = 0;
    wentries = 0;

    /* just write them in the first iteration if not allocating */
    if (*len > 0) {
        wentries = *len;
        curentry = *entries;
    }

    for (;;) {
        unsigned char rnlen;
        size_t namlen;
        memcpy(&rnlen, &buf[1], 1);
        /* control protocol permits up to 256, but that overflows */
        if (!rnlen) {
            namlen = 256;
        } else {
            namlen = rnlen;
        }
        ++nentries;
        /* if we're writing, write it */
        if (wentries) {
            fill_status(&buf[2], &curentry->status);
            memcpy(curentry->name, &buf[2 + sbufs], namlen);
            curentry->name[namlen] = '\0';
            ++curentry;
            --wentries;
        }
        cons += sbufs + namlen + 2;
        /* final entry */
        if (buf[sbufs + namlen + 2] == DINIT_RP_LISTDONE) {
            ++cons;
            break;
        }
        /* move on to next */
        buf += sbufs + namlen + 2;
    }

    /* we already wrote them */
    if (*len >= 0) {
        *len = nentries;
        goto do_ret;
    }

    /* otherwise allocate and loop again */
    *entries = malloc(sizeof(dinitctl_service_list_entry) * nentries);
    if (!*entries) {
        ret = -1;
        goto do_ret;
    }
    *len = nentries;
    curentry = *entries;

    buf = ctl->read_buf;

    for (size_t i = 0; i < nentries; ++i) {
        unsigned char rnlen;
        size_t namlen;
        memcpy(&rnlen, &buf[1], 1);
        if (!rnlen) {
            namlen = 256;
        } else {
            namlen = rnlen;
        }
        fill_status(&buf[2], &curentry->status);
        memcpy(curentry->name, &buf[2 + sbufs], namlen);
        curentry->name[namlen] = '\0';
        ++curentry;
        buf += sbufs + namlen + 2;
    }

do_ret:
    consume_recvbuf(ctl, cons);
    return ret;
}

static void setenv_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_setenv_finish(ctl);
}

DINITCTL_API int dinitctl_setenv(dinitctl *ctl, char const *env_var) {
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

static int setenv_check(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_RP_ACK) {
        return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_setenv_async(
    dinitctl *ctl, char const *env_var, dinitctl_async_cb cb, void *data
) {
    char *buf;
    char const *eq, *ev = NULL;
    struct dinitctl_op *qop;
    size_t varlen = strlen(env_var);
    size_t tlen = varlen;
    uint16_t vlen;

    if (!varlen) {
        errno = EINVAL;
        return -1;
    }
    eq = strchr(env_var, '=');
    if (eq == env_var) {
        errno = EINVAL;
        return -1;
    }
    if (!eq) {
        ev = getenv(env_var);
        tlen += 1;
        if (ev) {
            tlen += strlen(ev);
        }
    }
    if (tlen > 1021) {
        errno = EINVAL;
        return -1;
    }
    vlen = (uint16_t)tlen;

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, tlen + sizeof(vlen) + 1, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_SETENV;
    memcpy(&buf[1], &vlen, sizeof(vlen));
    memcpy(&buf[1 + sizeof(vlen)], env_var, varlen);
    if (tlen > varlen) {
        size_t idx = 1 + sizeof(vlen) + varlen;
        buf[idx++] = '=';
        if (ev) {
            memcpy(&buf[idx], ev, tlen - varlen - 1);
        }
    }

    qop->check_cb = &setenv_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_setenv_finish(dinitctl *ctl) {
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

static void shutdown_cb(dinitctl *ctl, void *data) {
    *((int *)data) = dinitctl_shutdown_finish(ctl);
}

DINITCTL_API int dinitctl_shutdown(dinitctl *ctl, enum dinitctl_shutdown_type type) {
    int ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    if (dinitctl_shutdown_async(ctl, type, &shutdown_cb, &ret) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret;
}

static int shutdown_check(dinitctl *ctl) {
    if (ctl->read_buf[0] == DINIT_RP_ACK) {
        return 0;
    }
    return -1;
}

DINITCTL_API int dinitctl_shutdown_async(
    dinitctl *ctl, enum dinitctl_shutdown_type type, dinitctl_async_cb cb, void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    switch (type) {
        case DINITCTL_SHUTDOWN_REMAIN:
        case DINITCTL_SHUTDOWN_HALT:
        case DINITCTL_SHUTDOWN_POWEROFF:
        case DINITCTL_SHUTDOWN_REBOOT:
            break;
        default:
            errno = EINVAL;
            return -1;
    }

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 2, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_SHUTDOWN;
    buf[1] = (char)type;

    qop->check_cb = &shutdown_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_shutdown_finish(dinitctl *ctl) {
    return consume_enum(ctl, DINITCTL_SUCCESS);
}

struct dirs_ret {
    char ***dirs;
    size_t *num_dirs;
    int code;
};

static void dirs_cb(dinitctl *ctl, void *data) {
    struct dirs_ret *ret = data;
    ret->code = dinitctl_query_service_dirs_finish(
        ctl, ret->dirs, ret->num_dirs
    );
}

DINITCTL_API int dinitctl_query_service_dirs(
    dinitctl *ctl, char ***dirs, size_t *num_dirs
) {
    struct dirs_ret ret;
    if (!bleed_queue(ctl)) {
        return -1;
    }
    ret.dirs = dirs;
    ret.num_dirs = num_dirs;
    if (dinitctl_query_service_dirs_async(ctl, &dirs_cb, &ret) < 0) {
        return -1;
    }
    if (!bleed_queue(ctl)) {
        return -1;
    }
    return ret.code;
}

static int dirs_check(dinitctl *ctl) {
    switch (ctl->read_buf[0]) {
        case DINIT_RP_LOADER_MECH:
            return 0;
        case DINIT_RP_ACK: {
            uint32_t psize;
            if (ctl->read_size < (sizeof(psize) + 2)) {
                return 1;
            }
            memcpy(&psize, &ctl->read_buf[2], sizeof(psize));
            return (ctl->read_size < psize);
        }
    }
    return -1;
}

DINITCTL_API int dinitctl_query_service_dirs_async(
    dinitctl *ctl, dinitctl_async_cb cb, void *data
) {
    char *buf;
    struct dinitctl_op *qop;

    qop = new_op(ctl);
    if (!qop) {
        return -1;
    }

    buf = reserve_sendbuf(ctl, 1, true);
    if (!buf) {
        return -1;
    }

    buf[0] = DINIT_CP_QUERY_LOAD_MECH;

    qop->check_cb = &dirs_check;
    qop->do_cb = cb;
    qop->do_data = data;

    queue_op(ctl, qop);

    return 0;
}

DINITCTL_API int dinitctl_query_service_dirs_finish(
    dinitctl *ctl, char ***dirs, size_t *num_dirs
) {
    int ret = DINITCTL_SUCCESS;
    char *buf, *tbuf, *sbuf, *abuf, **rbuf;
    char ltype;
    uint32_t psize, ndirs;
    size_t asize;

    if (ctl->read_buf[0] == DINIT_RP_NAK) {
        return consume_enum(ctl, DINITCTL_ERROR);
    }

    buf = ctl->read_buf + 1;

    ltype = *buf++;
    memcpy(&psize, buf, sizeof(psize));
    buf += sizeof(psize);

    /* SSET_TYPE_DIRLOAD */
    if (ltype != 1) {
        ret = DINITCTL_ERROR;
        goto do_ret;
    }

    memcpy(&ndirs, buf, sizeof(ndirs));
    buf += sizeof(ndirs);

    /* compute the total size we need to allocate */
    asize = (ndirs + 1) * sizeof(char *); /* pointers */

    /* go through the buffer to add the actual string lengths */
    tbuf = buf;
    for (size_t nleft = ndirs + 1; nleft; --nleft) {
        uint32_t slen;
        memcpy(&slen, tbuf, sizeof(slen));
        tbuf += sizeof(slen);
        tbuf += slen;
        asize += slen + 1; /* string with null termination */
    }

    /* now allocate a buffer big enough */
    abuf = malloc(asize);
    if (!abuf) {
        ret = -1;
        goto do_ret;
    }

    rbuf = (char **)abuf;
    sbuf = abuf + (ndirs + 1) * sizeof(char *);

    /* write all the strings */
    tbuf = buf;
    for (size_t nleft = ndirs + 1; nleft; --nleft) {
        uint32_t slen;
        memcpy(&slen, tbuf, sizeof(slen));
        tbuf += sizeof(slen);
        /* string goes in the string portion, terminated */
        memcpy(sbuf, tbuf, slen);
        sbuf[slen] = '\0';
        /* pointer to it goes in the pointer section */
        *rbuf++ = sbuf;
        /* move on to next string */
        sbuf += slen + 1;
        tbuf += slen;
    }

    /* done reading */
    *dirs = (char **)abuf;
    *num_dirs = ndirs + 1;

do_ret:
    consume_recvbuf(ctl, psize);
    return ret;
}
