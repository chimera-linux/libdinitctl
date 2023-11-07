#ifndef LIBDINITCTL_COMMON_H
#define LIBDINITCTL_COMMON_H

#include <libdinitctl.h>

/* initial buffer size for either buffer */
#define CTLBUF_SIZE 4096

struct dinitctl_op {
    int (*check_cb)(dinitctl_t *ctl);
    dinitctl_async_cb do_cb;
    void *do_data;
    void *finish_data;
    struct dinitctl_op *next;
};

struct dinitctl_t {
    /* linked list of queued operations */
    struct dinitctl_op *op_queue;
    struct dinitctl_op *op_last;
    struct dinitctl_op *op_avail;
    /* read-write buffer pair for dispatch */
    char *read_buf;
    char *write_buf;
    size_t read_size;
    size_t write_size;
    size_t read_cap;
    size_t write_cap;
    /* file descriptor of the dinitctl connection */
    int fd;
    int errnov;
};

#endif
