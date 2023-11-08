/** @file libdinitctl.h
 *
 * @brief The libdinitctl API.
 *
 * The libdinitctl project provides a high level API for the dinit service
 * manager control protocol. It provides synchronous and asynchronous API
 * and allows for easy integration into any program, regardless of what
 * event loop (if any) it uses.
 *
 * The synchronous API can be used directly. The asynchronous API need to
 * have a dispatch system in place, done by polling the file descriptor
 * returned from dinitctl_get_fd() for read/hup and then repeatedly
 * calling dinitctl_dispatch() with zero timeout until it returns 0.
 *
 * Synchronous APIs are wrappers around the asynchronous APIs, so they can
 * fail with any return code the asynchronous API would (any of the 3 APIs
 * making up async calls). Every synchronous API will first completely clear
 * the event queue (by blocking), performs the necessary actions, and clears
 * the event queue again.
 *
 * Nearly all APIs return an integer. Zero means success (#DINITCTL_SUCCESS),
 * a positive value means a recoverable error (one of the other #DINITCTL_ERROR
 * values) and a negative value means an unrecoverable error (in which case
 * errno is set and the connection should be aborted and reestablished).
 *
 * All responses may fail with ENOMEM (even if not mentioned) even if the
 * client has not run out of memory; this means dinit itself has run out of
 * memory. This is considered an unrecoverable condition, as it means the
 * connection will be closed by the remote side.
 *
 * @copyright See COPYING.md in the project tree.
 */

#ifndef LIBDINITCTL_H
#define LIBDINITCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define DINITCTL_API __attribute__((visibility("default")))
#else
#define DINITCTL_API
#endif

#include <stdint.h>
#include <stdbool.h>

typedef struct dinitctl_t dinitctl_t;
typedef uint32_t dinitctl_service_handle_t;

/** @brief General return values.
 *
 * These positive values may be returned by int-returning APIs.
 */
enum dinitctl_error {
    DINITCTL_SUCCESS = 0, /**< Success. */
    DINITCTL_ERROR, /**< Error. */
    DINITCTL_ERROR_SERVICE_MISSING, /**< Service could not be found. */
    DINITCTL_ERROR_SERVICE_DESC, /**< Service description error. */
    DINITCTL_ERROR_SERVICE_LOAD, /**< Service load error. */
};

/** @brief Service status flags.
 *
 * These are various flags that may be set on service status.
 */
enum dinitctl_service_flag {
    DINITCTL_SERVICE_FLAG_WAITING_FOR_CONSOLE = 1 << 0, /**< Waiting for console. */
    DINITCTL_SERVICE_FLAG_HAS_CONSOLE = 1 << 1, /**< Service has console. */
    DINITCTL_SERVICE_FLAG_WAS_START_SKIPPED = 1 << 2, /**< Service startup was skipped. */
    DINITCTL_SERVICE_FLAG_IS_MARKED_ACTIVE = 1 << 3, /**< Service was explicitly activated. */
    DINITCTL_SERVICE_FLAG_HAS_PID = 1 << 4, /**< Service has a PID. */
};

/* these enum values match dinit internally and are received by protocol */

/** @brief Service state. */
enum dinitctl_service_state {
    DINITCTL_SERVICE_STATE_STOPPED = 0, /**< Stopped. */
    DINITCTL_SERVICE_STATE_STARTING, /**< Currently starting. */
    DINITCTL_SERVICE_STATE_STARTED, /**< Started. */
    DINITCTL_SERVICE_STATE_STOPPING, /**< Currently stopping. */
};

/** @brief Service stop reason. */
enum dinitctl_service_stop_reason {
    DINITCTL_SERVICE_STOP_REASON_NORMAL = 0, /**< Normally stopped. */
    DINITCTL_SERVICE_STOP_REASON_DEP_RESTART, /**< Dependency has restarted. */
    DINITCTL_SERVICE_STOP_REASON_DEP_FAILED, /**< Dependency has failed. */
    DINITCTL_SERVICE_STOP_REASON_FAILED, /**< Service has failed. */
    DINITCTL_SERVICE_STOP_REASON_EXEC_FAILED, /**< Service has failed to launch. */
    DINITCTL_SERVICE_STOP_REASON_TIMEOUT, /**< Service has timed out. */
    DINITCTL_SERVICE_STOP_REASON_TERMINATED, /**< Service has terminated. */
};

/** @brief Service execution stage. */
enum dinitctl_service_exec_stage {
    DINITCTL_SERVICE_EXEC_STAGE_FDS = 0, /**< File descriptor setup. */
    DINITCTL_SERVICE_EXEC_STAGE_ENV, /**< Environment file is being read. */
    DINITCTL_SERVICE_EXEC_STAGE_READINESS, /**< Readiness notification. */
    DINITCTL_SERVICE_EXEC_STAGE_ACTIVATION_SOCKET, /**< Activation socket setup. */
    DINITCTL_SERVICE_EXEC_STAGE_CONTROL_SOCKET, /**< Control socket setup. */
    DINITCTL_SERVICE_EXEC_STAGE_CHDIR, /**< Directory change. */
    DINITCTL_SERVICE_EXEC_STAGE_STDIO, /**< Standard input/output setup. */
    DINITCTL_SERVICE_EXEC_STAGE_CGROUP, /**< Control group setup. */
    DINITCTL_SERVICE_EXEC_STAGE_RLIMITS, /**< Resource limits setup. */
    DINITCTL_SERVICE_EXEC_STAGE_UID_GID, /**< Privileges setup. */
};

/** @brief Service event type. */
enum dinitctl_service_event {
    DINITCTL_SERVICE_EVENT_STARTED = 0, /**< Service has started. */
    DINITCTL_SERVICE_EVENT_STOPPED, /**< Service has stopped. */
    DINITCTL_SERVICE_EVENT_START_FAILED, /**< Service startup has failed. */
    DINITCTL_SERVICE_EVENT_START_CANCELED, /**< Service startup has been canceled. */
    DINITCTL_SERVICE_EVENT_STOP_CANCELED, /**< Service stop has been canceled. */
};

/** @brief Shutdown type. */
enum dinitctl_shutdown_type {
    DINITCTL_SHUTDOWN_REMAIN = 1, /**< Continue running with no services. */
    DINITCTL_SHUTDOWN_HALT, /**< Halt system without powering down. */
    DINITCTL_SHUTDOWN_POWEROFF, /**< Power off system. */
    DINITCTL_SHUTDOWN_REBOOT, /**< Reboot system. */
};

/** @brief The async callback.
 *
 * Every async API consists of 3 calls. One is the primary invocation and
 * has the _async suffix. It will invoke the callback once it's ready to
 * finish. Inside the callback you should invoke the _finish API to get
 * the return value(s).
 */
typedef void (*dinitctl_async_cb)(dinitctl_t *ctl, void *data);

/** @brief Service event callback.
 *
 * The API makes it possible to subscribe to service events. Service
 * events attach service status to the event, similarly to explicit
 * event requests.
 *
 * One event callback is permitted per connection.
 */
typedef void (*dinitctl_service_event_cb)(
    dinitctl_t *ctl,
    dinitctl_service_handle_t handle,
    int service_event,
    int state,
    int target_state,
    pid_t pid,
    int flags,
    int stop_reason,
    int exec_stage,
    int exit_status,
    void *data
);

/** @brief Open the dinitctl socket.
 *
 * Open the socket at the given path. Like dinitctl_open_fd(), but
 * using a socket path. May fail with some more errnos, particularly
 * those from socket() and connect().
 *
 * @param socket_path The socket path.
 *
 * @return A dinitctl_t handle.
 */
DINITCTL_API dinitctl_t *dinitctl_open(char const *socket_path);

/** @brief Open a dinitctl handle via preopened file descriptor.
 *
 * Given a file descriptor (which must be an open connection to the
 * dinitctl socket and should be opened in non-blocking mode, otherwise
 * it will be made non-blocking), create a dinitctl handle for further use.
 *
 * The connection will be owned by the dinitctl handle and closed with
 * dinitctl_close().
 *
 * Allocates the necessary buffers and performs the initial version
 * check to make sure the protocol is compatible.
 *
 * May fail with any errnos returned from fcntl(), malloc(),
 * send(), recv(), and poll().
 *
 * @param fd A non-blocking connection to the dinitctl socket.
 *
 * @return A dinitctl handle.
 */
DINITCTL_API dinitctl_t *dinitctl_open_fd(int fd);

/** @brief Close a dinitctl handle.
 *
 * The handle must be valid. All resources associated with it will be freed.
 */
DINITCTL_API void dinitctl_close(dinitctl_t *ctl);

/** @brief Get the associated file descriptor.
 *
 * You should use this file descriptor with your event loop. You should
 * poll on POLLIN and POLLHUP, but not POLLOUT.
 *
 * This API always returns a valid file descriptor.
 *
 * @return The file descriptor.
 */
DINITCTL_API int dinitctl_get_fd(dinitctl_t *ctl);

/** @brief Dispatch events.
 *
 * This should be invoked (repeatedly) upon reception of data on the
 * file descriptor returned from dinitctl_get_fd().
 *
 * When using it from an event loop, the timeout should be 0, in which
 * case nothing will block. You can also wait indefinitely by making the
 * timeout -1, or wait a specific amount of milliseconds.
 *
 * If there is any pending data in the write buffer, it will be sent on
 * the socket (as much as possible without blocking). If there is any
 * pending data on the socket, it will be read. Any pending events will
 * be dispatched, stopping at the first event that does not have enough
 * data ready. If ops_left is non-NULL, it will be set to true if there
 * are still pending events after the invocation, and false otherwise.
 *
 * Optionally, this API can report whether there are still pending events
 * after its invocation.
 *
 * The function returns the number of events that have been processed. You
 * should keep calling it until the return value is zero.
 *
 * @param ctl The dinitctl.
 * @param timeout The timeout.
 * @param[out] ops_left Whether there are any events left.
 *
 * @return The number of events processed.
 */
DINITCTL_API int dinitctl_dispatch(dinitctl_t *ctl, int timeout, bool *ops_left);

/** @brief Set the service event callback.
 *
 * Sets the callback to be invoked upon reception of service events.
 *
 * This API cannot fail.
 */
DINITCTL_API void dinitctl_set_service_event_callback(dinitctl_t *ctl, dinitctl_service_event_cb cb, void *data);

/** @brief Find or load a service by name.
 *
 * Synchronous variant of dinitctl_load_service_async().
 *
 * @param ctl The dinitctl.
 * @param srv_name The service name.
 * @param find_only Whether to only locate the service.
 * @param[out] handle Where to store the result.
 * @param[out] state Optional service state.
 * @param[out] target_state Optional target state.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_load_service(dinitctl_t *ctl, char const *srv_name, bool find_only, dinitctl_service_handle_t *handle, int *state, int *target_state);

/** @brief Find or load a service by name.
 *
 * This will either load or just fine a service given srv_name, determined
 * by find_only. Once found, the callback will be invoked. Data passed here
 * will be passed to the callback.
 *
 * The only errors are EINVAL (service name too long) and ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param srv_name The service name.
 * @param find_only Whether to only locate the service.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_load_service_async(dinitctl_t *ctl, char const *srv_name, bool find_only, dinitctl_async_cb cb, void *data);

/** @brief Finish finding the service.
 *
 * Invoked from the callback to dinitctl_load_service_async().
 *
 * Stores the resulting handle. Optionally, it can store the service
 * state and target state, assuming those params are not NULL.
 *
 * The recoverable error codes are DINITCTL_ERROR_SERVICE_MISSING,
 * DINITCTL_ERROR_SERVICE_DESC, and DINITCTL_ERROR_SERVICE_LOAD.
 *
 * Unrecoverable errnos are EBADMSG (protocol error).
 *
 * @param ctl The dinitctl.
 * @param[out] handle The service handle to store.
 * @param[out] Optional service state.
 * @param[out] Optional service target state.
 *
 * @return 0 on success or one of the error codes.
 */
DINITCTL_API int dinitctl_load_service_finish(dinitctl_t *ctl, dinitctl_service_handle_t *handle, int *state, int *target_state);

/** @brief Get service name.
 *
 * Synchronous variant of dinitctl_get_service_name_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param[out] name The name.
 * @param[inout] buf_len Optional buffer length.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_get_service_name(dinitctl_t *ctl, dinitctl_service_handle_t handle, char **name, size_t *buf_len);

/** @brief Get service name.
 *
 * This will get the name of the given service, which was previously
 * found with dinitctl_load_service_async().
 *
 * May only fail with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_get_service_name_async(dinitctl_t *ctl, dinitctl_service_handle_t handle, dinitctl_async_cb cb, void *data);

/** @brief Finish getting the service name.
 *
 * Invoked from the callback to dinitctl_get_service_name_async().
 *
 * If buf_len contains a pointer to a valid value, name must contain a
 * pointer to a valid buffer of that length, and the name will be written
 * in it and potentially truncated (terminating zero will be written as
 * well, unless the buffer is empty). The buf_len will then be updated to
 * the actual length of the name (i.e. the minimum buffer size to store
 * the whole name, minus terminating zero).
 *
 * One exception to that is if buf_len points to a value of zero, in which
 * case this call is a pure length query, name is not touched at all, and
 * length is written.
 *
 * Otherwise, a new value will be allocated with malloc() and the user is
 * responsible for freeing it.
 *
 * May fail with DINITCTL_ERROR (in case of rejection by remote side)
 * or unrecoverably (with EBADMSG or general conditions).
 *
 * @param ctl The dinitctl.
 * @param[out] name The name.
 * @param[inout] buf_len Optional buffer length.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_get_service_name_finish(dinitctl_t *ctl, char **name, size_t *buf_len);

/** @brief Get service status.
 *
 * Synchronous variant of dinitctl_get_service_status_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param[out] state The service state.
 * @param[out] target_state The service target state.
 * @param[out] pid The service PID.
 * @param[out] flags The service flags.
 * @param[out] stop_reason The service stop reason.
 * @param[out] exec_stage The service exec stage.
 * @param[out] exit_status The service exit status or errno.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_get_service_status(dinitctl_t *ctl, dinitctl_service_handle_t handle, int *state, int *target_state, pid_t *pid, int *flags, int *stop_reason, int *exec_stage, int *exit_status);

/** @brief Get service status.
 *
 * This will get the status of the given service, which was previously
 * found with dinitctl_load_service_async().
 *
 * May only fail with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_get_service_status_async(dinitctl_t *ctl, dinitctl_service_handle_t handle, dinitctl_async_cb cb, void *data);

/** @brief Finish getting the service status.
 *
 * Invoked from the callback to dinitctl_get_service_status_async().
 *
 * All output params are optional.
 *
 * Stores the service state (always, one of dinitctl_service_state),
 * target state (ditto, if applicable, for transitioning services),
 * flags (dinitctl_service_flag, bitwise ORed). The others are set
 * depending on the status; pid will be set for services that have
 * it (see the flags), stop_reason will be set for stopped services,
 * exec_stage will be set for services whose execution failed, in
 * which case exit_status will be an errno, otherwise it will be
 * the exit status code for stopped services whose process failed.
 *
 * May fail with DINITCTL_ERROR (in case of rejection by remote side)
 * or unrecoverably (with EBADMSG or general conditions).
 *
 * @param ctl The dinitctl.
 * @param[out] state The service state.
 * @param[out] target_state The service target state.
 * @param[out] pid The service PID.
 * @param[out] flags The service flags.
 * @param[out] stop_reason The service stop reason.
 * @param[out] exec_stage The service exec stage.
 * @param[out] exit_status The service exit status or errno.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_get_service_status_finish(dinitctl_t *ctl, int *state, int *target_state, pid_t *pid, int *flags, int *stop_reason, int *exec_stage, int *exit_status);

/** @brief Set the trigger value of a service.
 *
 * Synchronous variant of dinitctl_set_service_trigger_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param trigger The trigger value.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_set_service_trigger(dinitctl_t *ctl, dinitctl_service_handle_t handle, bool trigger);

/** @brief Set the trigger value of a service.
 *
 * This sets or unsets whether a service is triggered, depending on the
 * given value.
 *
 * This API may only fail with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param trigger The trigger value.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_set_service_trigger_async(dinitctl_t *ctl, dinitctl_service_handle_t handle, bool trigger, dinitctl_async_cb cb, void *data);

/** @brief Finish setting trigger value.
 *
 * Invoked from the callback to dinitctl_set_service_trigger_async().
 *
 * May fail with DINITCTL_ERROR recoverably, or with EBADMSG (protocol error)
 * unrecoverably.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_set_service_trigger_finish(dinitctl_t *ctl);

/** @brief Set an environment variable in the dinit environment.
 *
 * Synchronous variant of dinitctl_setenv_async().
 *
 * @param ctl The dinitctl.
 * @param env_var The env var to set.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_setenv(dinitctl_t *ctl, char const *env_var);

/** @brief Set an environment variable in the dinit environment.
 *
 * This sets an environment variable in the dinit activation environment.
 * It cannot unset a variable. The variable must have the format VAR=val,
 * or just VAR (in which case the current environment's value will be
 * used).
 *
 * This API may only fail with EINVAL if the input value is too long, or
 * with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param env_var The env var to set.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_setenv_async(dinitctl_t *ctl, char const *env_var, dinitctl_async_cb cb, void *data);

/** @brief Finish setting the env var.
 *
 * Invoked from the callback to dinitctl_setenv_async().
 *
 * May fail with DINITCTL_ERROR recoverably, or with EBADMSG (protocol error)
 * unrecoverably.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_setenv_finish(dinitctl_t *ctl);

/** @brief Shut down dinit and maybe system.
 *
 * Synchronous variant of dinitctl_shutdown_async().
 *
 * @param ctl The dinitctl.
 * @param int The shutdown type.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_shutdown(dinitctl_t *ctl, int type);

/** @brief Shut down dinit and maybe system.
 *
 * This issues a shutdown command. It may result in the system being
 * shut down or rebooted, or it may just tell dinit to shut down all services.
 *
 * This API may only fail with EINVAL if the input value is invalid, or
 * with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param type The shutdown type.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_shutdown_async(dinitctl_t *ctl, int type, dinitctl_async_cb cb, void *data);

/** @brief Finish the shutdown command.
 *
 * Invoked from the callback to dinitctl_shutdown_async().
 *
 * May fail with DINITCTL_ERROR recoverably, or with EBADMSG (protocol error)
 * unrecoverably.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_shutdown_finish(dinitctl_t *ctl);

#ifdef __cplusplus
}
#endif

#endif
