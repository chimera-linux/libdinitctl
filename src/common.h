#ifndef LIBDINITCTL_COMMON_H
#define LIBDINITCTL_COMMON_H

#include <libdinitctl.h>

/* initial buffer size for either buffer */
#define CTLBUF_SIZE 4096

/* should be more than enough */
#define HANDLE_BUCKETN 32
#define HANDLE_CHUNKN 16

struct dinitctl_op {
    int (*check_cb)(dinitctl *ctl);
    dinitctl_async_cb do_cb;
    void *do_data;
    struct dinitctl_op *next;
    dinitctl_service_handle *handle;
    int errnov;
    bool flag;
};

struct dinitctl_service_handle {
    uint32_t idx;
    dinitctl_service_handle *next;
};

struct dinitctl_handle_chunk {
    dinitctl_service_handle data[HANDLE_CHUNKN];
    struct dinitctl_handle_chunk *next;
};

struct dinitctl {
    /* service event callback */
    dinitctl_service_event_cb sv_event_cb;
    void *sv_event_data;
    /* linked list of queued operations */
    struct dinitctl_op *op_queue;
    struct dinitctl_op *op_last;
    struct dinitctl_op *op_avail;
    /* handle table */
    dinitctl_service_handle *hndl_map[HANDLE_BUCKETN];
    dinitctl_service_handle *hndl_unused;
    struct dinitctl_handle_chunk *hndl_chunk;
    /* read-write buffer pair for dispatch */
    char *read_buf;
    char *write_buf;
    size_t read_size;
    size_t write_size;
    size_t read_cap;
    size_t write_cap;
    /* file descriptor of the dinitctl connection */
    int fd;
};

#endif
