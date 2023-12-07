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
 * Asynchronous APIs will only ever run their final callback if a recoverable
 * condition is encountered; that means the finish APIs will only ever return
 * success, recoverable failure, or a system failure (e.g. failed allocation)
 * for specific APIs. Synchronous APIs also report errors of the dispatch loop.
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

/** @brief The dinitctl handle.
 *
 * This opaque object represents a connection to a dinit socket
 * along with event queues and other auxiliary data.
 */
typedef struct dinitctl dinitctl;

/** @brief The dinitctl service handle.
 *
 * A service handle represents a connection's reference to a loaded
 * service. The handles are cached at the client side and always in
 * sync with the server. A valid handle existing in any connection
 * will prevent a service from being unloaded or reloaded.
 *
 * Ideally, a handle will have a short lifetime, so that it does not
 * unnecessarily hold services in place. A handle is created by loading
 * or finding the service, after which it can be used in subsequent
 * calls. Once done, it should be closed.
 *
 * APIs that take a handle as an input will fail with EINVAL if a bad
 * handle is given.
 *
 * Unloading or reloading a service will close the handle upon success.
 */
typedef struct dinitctl_service_handle dinitctl_service_handle;

/** @brief General return values.
 *
 * These positive values may be returned by int-returning APIs.
 */
enum dinitctl_error {
    DINITCTL_SUCCESS = 0, /**< Success. */
    DINITCTL_ERROR, /**< Error. */
    DINITCTL_ERROR_SHUTTING_DOWN, /**< Services are shutting down. */
    DINITCTL_ERROR_SERVICE_MISSING, /**< Service could not be found. */
    DINITCTL_ERROR_SERVICE_DESC, /**< Service description error. */
    DINITCTL_ERROR_SERVICE_LOAD, /**< Service load error. */
    DINITCTL_ERROR_SERVICE_NO_PID, /**< Service has no PID. */
    DINITCTL_ERROR_SERVICE_BAD_SIGNAL, /**< Signal out of range. */
    DINITCTL_ERROR_SERVICE_SIGNAL_FAILED, /**< Signal has failed. */
    DINITCTL_ERROR_SERVICE_PINNED, /**< Service is pinned. */
    DINITCTL_ERROR_SERVICE_ALREADY, /**< Service already in that state. */
    DINITCTL_ERROR_SERVICE_DEPENDENTS, /**< Dependents are blocking stop request. */
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

/** @brief Dependency type. */
enum dinitctl_dependency_type {
    DINITCTL_DEPENDENCY_REGULAR = 0, /**< Regular hard dependency. */
    DINITCTL_DEPENDENCY_WAITS_FOR = 2, /**< "Waits for" dependency. */
    DINITCTL_DEPENDENCY_MILESTONE, /**< Milestone dependency. */
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

/** @brief Log buffer flags. */
enum dinitctl_log_buffer_flag {
    DINITCTL_LOG_BUFFER_CLEAR = 1 << 0, /** Clear the log buffer. */
};

/** @brief Service status.
 *
 * This structure contains all the known information about dinit
 * service status. It may be passed to event callbacks, it may
 * be returned by explicit status requests, or by listings.
 *
 * Not all fields may be filled in, as it is dependent on the current
 * service state and/or the flags. Fields that are not filled in are
 * still safe to read, but may contain unhelpful values (typically
 * zeroes).
 *
 * The state is always filled. The target_state applies to transitioning
 * services. The flags are bitwise-ORed. PID will be set for services
 * that have it (see flags), stop_reason will be set for stopped services
 * only, and exec_stage will be set for services whose execution failed.
 * For those, exit_status will be an errno value. For other stopped services,
 * exit_status will be the exit status code of the process.
 */
typedef struct dinitctl_service_status {
    pid_t pid; /**< The service PID. */
    enum dinitctl_service_state state; /**< The current state. */
    enum dinitctl_service_state target_state; /**< The target state. */
    enum dinitctl_service_stop_reason stop_reason; /**< The dinitctl_service_stop_reason. */
    enum dinitctl_service_exec_stage exec_stage; /**< The dinitctl_service_exec_stage. */
    int flags; /**< Any dinitctl_service_flags. */
    int exit_status; /**< Exit code or errno, depending on stop_reason. */
} dinitctl_service_status;

/** @brief Service list entry.
 *
 * This is used by dinitctl_list_services() APIs as the result. It
 * contains the service status and a name (of maximum of 256 characters,
 * plus a terminating zero).
 */
typedef struct dinitctl_service_list_entry {
    dinitctl_service_status status;
    char name[257];
} dinitctl_service_list_entry;

/** @brief The async callback.
 *
 * Every async API consists of 3 calls. One is the primary invocation and
 * has the _async suffix. It will invoke the callback once it's ready to
 * finish. Inside the callback you should invoke the _finish API to get
 * the return value(s).
 */
typedef void (*dinitctl_async_cb)(dinitctl *ctl, void *data);

/** @brief Service event callback.
 *
 * The API makes it possible to subscribe to service events. Service
 * events attach service status to the event, similarly to explicit
 * event requests.
 *
 * One event callback is permitted per connection.
 */
typedef void (*dinitctl_service_event_cb)(
    dinitctl *ctl,
    dinitctl_service_handle *handle,
    enum dinitctl_service_event service_event,
    dinitctl_service_status const *status,
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
 * @return A dinitctl handle.
 */
DINITCTL_API dinitctl *dinitctl_open(char const *socket_path);

/** @brief Open the system dinitctl socket.
 *
 * Like dinitctl_open(), but using the system socket path the library
 * was built with (which should match what dinit was built with). A
 * default system dinit must be running for this to succeed.
 *
 * @return A dinitctl handle.
 */
DINITCTL_API dinitctl *dinitctl_open_system(void);

/** @brief Open the user dinitctl socket.
 *
 * Like dinitctl_open(), but using the default user socket path. The
 * logic to determine the user socket path is the same as in the dinit
 * codebase. A default user dinit must be running for this to succeed.
 *
 * @return A dinitctl handle.
 */
DINITCTL_API dinitctl *dinitctl_open_user(void);

/** @brief Open the default dinitctl socket.
 *
 * For root user, this is dinitctl_open_system(). For any other user,
 * this is dinitctl_open_user().
 *
* @return A dinitctl handle.
 */
DINITCTL_API dinitctl *dinitctl_open_default(void);

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
DINITCTL_API dinitctl *dinitctl_open_fd(int fd);

/** @brief Close a dinitctl handle.
 *
 * The handle must be valid. All resources associated with it will be freed.
 */
DINITCTL_API void dinitctl_close(dinitctl *ctl);

/** @brief Get the associated file descriptor.
 *
 * You should use this file descriptor with your event loop. You should
 * poll on POLLIN and POLLHUP, but not POLLOUT.
 *
 * This API always returns a valid file descriptor.
 *
 * @return The file descriptor.
 */
DINITCTL_API int dinitctl_get_fd(dinitctl *ctl);

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
 * Upon unrecoverable error, this function returns a negative value. An
 * unrecoverable error may be the other side closing the connection,
 * a system error like an allocation failure, or a protocol error while
 * handling events. For those cases, errno will be set.
 *
 * @param ctl The dinitctl.
 * @param timeout The timeout.
 * @param[out] ops_left Whether there are any events left.
 *
 * @return The number of events processed.
 */
DINITCTL_API int dinitctl_dispatch(dinitctl *ctl, int timeout, bool *ops_left);

/** @brief Set the service event callback.
 *
 * Sets the callback to be invoked upon reception of service events.
 *
 * This API cannot fail.
 */
DINITCTL_API void dinitctl_set_service_event_callback(dinitctl *ctl, dinitctl_service_event_cb cb, void *data);

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
DINITCTL_API int dinitctl_load_service(dinitctl *ctl, char const *srv_name, bool find_only, dinitctl_service_handle **handle, enum dinitctl_service_state *state, enum dinitctl_service_state *target_state);

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
DINITCTL_API int dinitctl_load_service_async(dinitctl *ctl, char const *srv_name, bool find_only, dinitctl_async_cb cb, void *data);

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
 * May possibly fail with ENOMEM unrecoverably.
 *
 * @param ctl The dinitctl.
 * @param[out] handle The service handle to store.
 * @param[out] Optional service state.
 * @param[out] Optional service target state.
 *
 * @return 0 on success or one of the error codes.
 */
DINITCTL_API int dinitctl_load_service_finish(dinitctl *ctl, dinitctl_service_handle **handle, enum dinitctl_service_state *state, enum dinitctl_service_state *target_state);

/** @brief Unload or reload a service.
 *
 * Synchronous variant of dinitctl_unload_service_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param reload Whether to reload the service.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_unload_service(dinitctl *ctl, dinitctl_service_handle *handle, bool reload);

/** @brief Unload or reload a service.
 *
 * This will unload or reload the given service, which was previously
 * found with dinitctl_load_service_async().
 *
 * May fail with EINVAL or with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param reload Whether to reload the service.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_unload_service_async(dinitctl *ctl, dinitctl_service_handle *handle, bool reload, dinitctl_async_cb cb, void *data);

/** @brief Finish unloading or reloading the service name.
 *
 * Invoked from the callback to dinitctl_unload_service_async().
 *
 * May fail with DINITCTL_ERROR (in case of rejection by remote side).
 * No unrecoverable errors are possible.
 *
 * A successful return means the original given handle was closed and
 * must not be used again.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive error code.
 */
DINITCTL_API int dinitctl_unload_service_finish(dinitctl *ctl);

/** @brief Close a service handle.
 *
 * Synchronous variant of dinitctl_close_service_handle_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_close_service_handle(dinitctl *ctl, dinitctl_service_handle *handle);

/** @brief Close a service handle.
 *
 * Start closing the given service handle. The handle must be known
 * to the client, i.e. it must represent a service that was loaded
 * or found and not unloaded.
 *
 * May fail with EINVAL (if the handle is not known to the client)
 * or with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_close_service_handle_async(dinitctl *ctl, dinitctl_service_handle *handle, dinitctl_async_cb cb, void *data);

/** @brief Finish closing the service handle.
 *
 * Invoked from the callback to dinitctl_unload_service_async().
 *
 * This call may not fail.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success.
 */
DINITCTL_API int dinitctl_close_service_handle_finish(dinitctl *ctl);

/** @brief Try starting a service.
 *
 * Synchronous variant of dinitctl_start_service_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service started.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_start_service(dinitctl *ctl, dinitctl_service_handle *handle, bool pin);

/** @brief Try starting a service.
 *
 * This will attempt explicit service startup. If a pin is specified,
 * it will not be possible to stop the service (though its explicit
 * activation mark can be removed, via stop or release). The pin is
 * however removed upon failed startup.
 *
 * May fail with EINVAL or ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service started.
 * @param cb The callback.
 * @param data The data to tpass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_start_service_async(dinitctl *ctl, dinitctl_service_handle *handle, bool pin, dinitctl_async_cb cb, void *data);

/** @brief Finish the startup request.
 *
 * Invoked from the callback to dinitctl_start_service_async().
 *
 * Keep in mind that this is merely a request, and no wait until
 * the service has reached the requested state is done. If you wish
 * to do that, you should subscribe to service events via the dedicated
 * callback dinitctl_set_service_event_callback() and watch for the
 * requested state on the handle.
 *
 * May fail with DINITCTL_ERROR_SHUTTING_DOWN (service set is already being
 * shut down), DINITCTL_ERROR_SERVICE_PINNED (service is pinned stopped) or
 * maybe DINITCTL_ERROR_SERVICE_ALREADY (service is already started). May not
 * fail unrecoverably.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_start_service_finish(dinitctl *ctl);

/** @brief Try stopping a service.
 *
 * Synchronous variant of dinitctl_stop_service_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service stopped.
 * @param restart Whether to restart the service.
 * @param gentle Whether to check dependents first.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_stop_service(dinitctl *ctl, dinitctl_service_handle *handle, bool pin, bool restart, bool gentle);

/** @brief Try stopping a service.
 *
 * This will attempt explicit service stop. If a pin is specified,
 * it will not be possible to start the service, hard dependents will
 * fail to start, and explicit start command will have no effect.
 *
 * If restart is specified, the service will be restarted after stopping,
 * and any specified pin value will be ignored. If gentle is specified,
 * the stop will fail if there are running hard dependents.
 *
 * May fail with EINVAL or with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service stopped.
 * @param restart Whether to restart the service.
 * @param gentle Whether to check dependents first.
 * @param cb The callback.
 * @param data The data to tpass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_stop_service_async(dinitctl *ctl, dinitctl_service_handle *handle, bool pin, bool restart, bool gentle, dinitctl_async_cb cb, void *data);

/** @brief Finish the stop request.
 *
 * Invoked from the callback to dinitctl_stop_service_async().
 *
 * Keep in mind that this is merely a request, and no wait until
 * the service has reached the requested state is done. If you wish
 * to do that, you should subscribe to service events via the dedicated
 * callback dinitctl_set_service_event_callback() and watch for the
 * requested state on the handle.
 *
 * May fail with DINITCTL_ERROR_SHUTTING_DOWN (service set is already being
 * shut down), DINITCTL_ERROR_SERVICE_PINNED (service is pinned started), as
 * well as DINITCTL_ERROR_SERVICE_DEPENDENTS if gentle stop was requested and
 * any hard dependents are started, or maybe DINITCTL_ERROR_SERVICE_ALREADY
 * (service is already stopped). If restart was requested, it may also
 * fail with DINITCTL_ERROR if the restart request failed. May not fail
 * unrecoverably.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_stop_service_finish(dinitctl *ctl);

/** @brief Try waking a service.
 *
 * Synchronous variant of dinitctl_wake_service_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service in place.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_wake_service(dinitctl *ctl, dinitctl_service_handle *handle, bool pin);

/** @brief Try waking a service.
 *
 * If there are any started dependents for this service (even soft
 * dependencies) and the service ist stopped, it will start. The
 * service will not be marked explicitly activated and will stop
 * as soon as dependents stop.
 *
 * If a pin is specified, it will be pinned started.
 *
 * May fail with EINVAL or ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service started.
 * @param cb The callback.
 * @param data The data to tpass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_wake_service_async(dinitctl *ctl, dinitctl_service_handle *handle, bool pin, dinitctl_async_cb cb, void *data);

/** @brief Finish the wake request.
 *
 * Invoked from the callback to dinitctl_wake_service_async().
 *
 * Keep in mind that this is merely a request, and no wait until
 * the service has reached the requested state is done. If you wish
 * to do that, you should subscribe to service events via the dedicated
 * callback dinitctl_set_service_event_callback() and watch for the
 * requested state on the handle.
 *
 * May fail with DINITCTL_ERROR_SHUTTING_DOWN (service set is already being
 * shut down), DINITCTL_ERROR_SERVICE_PINNED (service is pinned stopped) or
 * maybe DINITCTL_ERROR_SERVICE_ALREADY (service is already started). May also
 * fail with DINITCTL_ERROR if no dependent that would wake it is found. May
 * not fail unrecoverably.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_wake_service_finish(dinitctl *ctl);

/** @brief Try releasing a service.
 *
 * Synchronous variant of dinitctl_release_service_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service stopped.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_release_service(dinitctl *ctl, dinitctl_service_handle *handle, bool pin);

/** @brief Try releasing a service.
 *
 * This will clear explicit activation mark from the service. That
 * means if there are no started dependents, the service will stop.
 * Otherwise, it will stop as soon as dependents stop. If a pin is
 * specified, the service will be pinned stopped.
 *
 * May fail with EINVAL or ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param pin Whether to pin the service stopped.
 * @param cb The callback.
 * @param data The data to tpass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_release_service_async(dinitctl *ctl, dinitctl_service_handle *handle, bool pin, dinitctl_async_cb cb, void *data);

/** @brief Finish the release request.
 *
 * Invoked from the callback to dinitctl_release_service_async().
 *
 * Keep in mind that this is merely a requeest, and no wait until
 * the service has reached the requested state is done. If you wish
 * to do that, you should subscribe to service events via the dedicated
 * callback dinitctl_set_service_event_callback() and watch for the
 * requested state on the handle.
 *
 * May fail with DINITCTL_ERROR_SERVICE_ALREADY (service is already started).
 * May not fail unrecoverably.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_release_service_finish(dinitctl *ctl);

/** @brief Remove start/stop service pins.
 *
 * Synchronous variant of dinitctl_unpin_service_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_unpin_service(dinitctl *ctl, dinitctl_service_handle *handle);

/** @brief Remove start/stop service pins.
 *
 * This will clear start and/or stop pins from a service. If the service
 * is started, is not explicitly activated, and has no active dependents,
 * it will stop. If the service is stopped and has a dependent service
 * that is starting, it will start. Otherwise, any pending start/stop
 * will be done.
 *
 * May only fail with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param cb The callback.
 * @param data The data to tpass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_unpin_service_async(dinitctl *ctl, dinitctl_service_handle *handle, dinitctl_async_cb cb, void *data);

/** @brief Finish the unpin.
 *
 * Invoked from the callback to dinitctl_unpin_service_async().
 *
 * Keep in mind that no state change wait is performed. This call
 * may also not fail.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero.
 */
DINITCTL_API int dinitctl_unpin_service_finish(dinitctl *ctl);

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
DINITCTL_API int dinitctl_get_service_name(dinitctl *ctl, dinitctl_service_handle *handle, char **name, ssize_t *buf_len);

/** @brief Get service name.
 *
 * This will get the name of the given service, which was previously
 * found with dinitctl_load_service_async().
 *
 * May fail with EINVAL or ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_get_service_name_async(dinitctl *ctl, dinitctl_service_handle *handle, dinitctl_async_cb cb, void *data);

/** @brief Finish getting the service name.
 *
 * Invoked from the callback to dinitctl_get_service_name_async().
 *
 * The buf_len parameter is expected to always point to a valid value.
 * If the value is negative, it means the storage for name should be
 * allocated (and the user will be responsible for freeing it).
 *
 * Otherwise name is expected to point to a pre-allocated buffer of the
 * given length, and the name will be written there and potentially
 * truncated. The buf_len will be updated to the actual length of the
 * name (without a terminating zero) regardless of if there is enough
 * storage for it.
 *
 * If the given buffer length is zero, name is not touched at all, and
 * the name length will still be updated. This is essentially a pure length
 * query.
 *
 * May fail with DINITCTL_ERROR (in case of rejection by remote side) or
 * with ENOMEM if the name needs allocation and it fails.
 *
 * @param ctl The dinitctl.
 * @param[out] name The name.
 * @param[inout] buf_len Optional buffer length.
 *
 * @return Zero on success or a positive error code.
 */
DINITCTL_API int dinitctl_get_service_name_finish(dinitctl *ctl, char **name, ssize_t *buf_len);

/** @brief Get service log buffer.
 *
 * Synchronous variant of dinitctl_get_service_log_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param flags The flags.
 * @param[out] log The log buffer.
 * @param[inout] buf_len Optional buffer length.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_get_service_log(dinitctl *ctl, dinitctl_service_handle *handle, int flags, char **log, ssize_t *buf_len);

/** @brief Get service log buffer.
 *
 * This will get the log buffer of the given service, which was previously
 * found with dinitctl_load_service_async(). The service log type must be
 * set to buffer, or the retrieval will fail.
 *
 * The only supported flag right now is DINITCTL_LOG_BUFFER_CLEAR, which
 * will clear the log after retrieving it. You can pass 0 for flags if
 * you don't want that.
 *
 * May only fail with ENOMEM or with EINVAL if the flags or handle are invalid.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param flags The flags.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_get_service_log_async(dinitctl *ctl, dinitctl_service_handle *handle, int flags, dinitctl_async_cb cb, void *data);

/** @brief Finish getting the service log buffer.
 *
 * Invoked from the callback to dinitctl_get_service_log_async().
 *
 * The buf_len parameter is expected to always point to a valid value.
 * If the value is negative, it means the storage for log should be
 * allocated (and the user will be responsible for freeing it).
 *
 * Otherwise log is expected to point to a pre-allocated buffer of the
 * given length, and the log will be written there and potentially
 * truncated. The buf_len will be updated to the actual length of the
 * log (without a terminating zero) regardless of if there is enough
 * storage for it.
 *
 * If the given buffer length is zero, log is not touched at all, and
 * the log length will still be updated. This is essentially a pure length
 * query.
 *
 * May fail with DINITCTL_ERROR (in case of rejection by remote side) or
 * with ENOMEM if the log needs allocation and it fails.
 *
 * @param ctl The dinitctl.
 * @param[out] log The log buffer.
 * @param[inout] buf_len Optional buffer length.
 *
 * @return Zero on success or a positive error code.
 */
DINITCTL_API int dinitctl_get_service_log_finish(dinitctl *ctl, char **log, ssize_t *buf_len);

/** @brief Get service status.
 *
 * Synchronous variant of dinitctl_get_service_status_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param[out] status The status.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_get_service_status(dinitctl *ctl, dinitctl_service_handle *handle, dinitctl_service_status *status);

/** @brief Get service status.
 *
 * This will get the status of the given service, which was previously
 * found with dinitctl_load_service_async().
 *
 * May fail with EINVAL or ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_get_service_status_async(dinitctl *ctl, dinitctl_service_handle *handle, dinitctl_async_cb cb, void *data);

/** @brief Finish getting the service status.
 *
 * Invoked from the callback to dinitctl_get_service_status_async().
 *
 * Stores the service status in the output parameter.
 *
 * May fail with DINITCTL_ERROR (in case of rejection by remote side).
 * No unrecoverable errors are possible.
 *
 * @param ctl The dinitctl.
 * @param[out] status The status.
 *
 * @return Zero on success or a positive error code.
 */
DINITCTL_API int dinitctl_get_service_status_finish(dinitctl *ctl, dinitctl_service_status *status);

/** @brief Link two services together, or unlink them.
 *
 * Synchronous variant of dinitctl_add_service_dependency_async().
 *
 * @param ctl The dinitctl.
 * @param from_handle The service to gain the dependency.
 * @param to_handle The service to become the dependency.
 * @param type The dependency type.
 * @param remove Whether to remove the dependency.
 * @param enable Whether to start the dependency.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_add_remove_service_dependency(dinitctl *ctl, dinitctl_service_handle *from_handle, dinitctl_service_handle *to_handle, enum dinitctl_dependency_type type, bool remove, bool enable);

/** @brief Link two services together, or unlink them.
 *
 * The from_handle will gain a dependency on to_handle. If enable is
 * specified, the dependency will also be started (as if `dinitctl enable`)
 * but only if the from_handle is started or starting already. If remove
 * is specified, the dependency will be removed rather than added, and
 * enable cannot be specified.
 *
 * This API may fail with ENOMEM or with EINVAL if the given dependency
 * type is not valid or the handles are not valid (or if enable and remove
 * are specified together).
 *
 * @param ctl The dinitctl.
 * @param from_handle The service to gain the dependency.
 * @param to_handle The service to become the dependency.
 * @param type The dependency type.
 * @param remove Whether to remove the dependency.
 * @param enable Whether to start the dependency.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_add_remove_service_dependency_async(dinitctl *ctl, dinitctl_service_handle *from_handle, dinitctl_service_handle *to_handle, enum dinitctl_dependency_type type, bool remove, bool enable, dinitctl_async_cb cb, void *data);

/** @brief Finish the dependency setup.
 *
 * Invoked from the callback to dinitctl_add_service_dependency_async().
 *
 * May fail with DINITCTL_ERROR if the dependency cannot be created, for
 * instance if the dependency states contradict or if it would create a
 * loop, or if it cannot be removed.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive error code.
 */
DINITCTL_API int dinitctl_add_remove_service_dependency_finish(dinitctl *ctl);

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
DINITCTL_API int dinitctl_set_service_trigger(dinitctl *ctl, dinitctl_service_handle *handle, bool trigger);

/** @brief Set the trigger value of a service.
 *
 * This sets or unsets whether a service is triggered, depending on the
 * given value.
 *
 * This API may fail with EINVAL or ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param trigger The trigger value.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_set_service_trigger_async(dinitctl *ctl, dinitctl_service_handle *handle, bool trigger, dinitctl_async_cb cb, void *data);

/** @brief Finish setting trigger value.
 *
 * Invoked from the callback to dinitctl_set_service_trigger_async().
 *
 * May fail with DINITCTL_ERROR recoverably. No unrecoverable errors
 * are possible.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive error code.
 */
DINITCTL_API int dinitctl_set_service_trigger_finish(dinitctl *ctl);

/** @brief Send a service a signal.
 *
 * Synchronous variant of dinitctl_signal_service_async().
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param signum The signal value.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_signal_service(dinitctl *ctl, dinitctl_service_handle *handle, int signum);

/** @brief Send a service a signal.
 *
 * This sends the given signal to the given service.
 *
 * This API may fail with EINVAL or ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param handle The service handle.
 * @param signum The signal value.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_signal_service_async(dinitctl *ctl, dinitctl_service_handle *handle, int signum, dinitctl_async_cb cb, void *data);

/** @brief Finish signaling the service.
 *
 * Invoked from the callback to dinitctl_service_signal_async().
 *
 * May fail with DINITCTL_ERROR if the input handle is rejected, or
 * with DINITCTL_ERROR_SERVICE_NO_PID if the service has no PID to signal,
 * with DINITCTL_ERROR_SERVICE_SIGNAL_FAILED if the signaling failed,
 * or with DINITCTL_ERROR_SERVICE_BAD_SIGNAL if the input signal was bad.
 * No unrecoverable errors are possible.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero on success or a positive error code.
 */
DINITCTL_API int dinitctl_signal_service_finish(dinitctl *ctl);

/** @brief List services.
 *
 * Synchronous variant of dinitctl_list_services_async().
 *
 * @param ctl The dinitctl.
 * @param[out] entries The list entries.
 * @param[inout] len Optional number of entries.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_list_services(dinitctl *ctl, dinitctl_service_list_entry **entries, ssize_t *len);

/** @brief List services.
 *
 * This will fetch all loaded services' statuses.
 *
 * May only fail with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_list_services_async(dinitctl *ctl, dinitctl_async_cb cb, void *data);

/** @brief Finish listing the services.
 *
 * Invoked from the callback to dinitctl_list_services_async().
 *
 * The llen parameter is expected to always point to a valid value.
 * If the value is negative, it means the storage for entries should be
 * allocated (and the user will be responsible for freeing it).
 *
 * Otherwise entries is expected to point to a pre-allocated buffer of
 * len entries, and the entries will be written there up to len. The len
 * will be updated to the actual number of entries egardless of if there
 * is enough storage for it.
 *
 * If len is zero, entries is not touched at all, and the number will still
 * be updated. This is essentially a pure count query.
 *
 * May fail only with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param[out] entries The list entries.
 * @param[inout] len Optional number of entries.
 *
 * @return Zero on success or a negative error code.
 */
DINITCTL_API int dinitctl_list_services_finish(dinitctl *ctl, dinitctl_service_list_entry **entries, ssize_t *len);

/** @brief Set an environment variable in the dinit environment.
 *
 * Synchronous variant of dinitctl_setenv_async().
 *
 * @param ctl The dinitctl.
 * @param env_var The env var to set.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_setenv(dinitctl *ctl, char const *env_var);

/** @brief Set an environment variable in the dinit environment.
 *
 * This sets an environment variable in the dinit activation environment.
 * It cannot unset a variable. The variable must have the format VAR=val,
 * or just VAR (in which case the current environment's value will be
 * used).
 *
 * This API may only fail with EINVAL if the input value is too long or has
 * an invalid format, or with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param env_var The env var to set.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_setenv_async(dinitctl *ctl, char const *env_var, dinitctl_async_cb cb, void *data);

/** @brief Finish setting the env var.
 *
 * Invoked from the callback to dinitctl_setenv_async().
 *
 * This call may not fail.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero.
 */
DINITCTL_API int dinitctl_setenv_finish(dinitctl *ctl);

/** @brief Shut down dinit and maybe system.
 *
 * Synchronous variant of dinitctl_shutdown_async().
 *
 * @param ctl The dinitctl.
 * @param int The shutdown type.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_shutdown(dinitctl *ctl, enum dinitctl_shutdown_type type);

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
DINITCTL_API int dinitctl_shutdown_async(dinitctl *ctl, enum dinitctl_shutdown_type type, dinitctl_async_cb cb, void *data);

/** @brief Finish the shutdown command.
 *
 * Invoked from the callback to dinitctl_shutdown_async().
 *
 * This call may not fail.
 *
 * @param ctl The dinitctl.
 *
 * @return Zero.
 */
DINITCTL_API int dinitctl_shutdown_finish(dinitctl *ctl);

/** @brief Get the working directory and service dirs of dinit.
 *
 * Synchronous variant of dinitctl_query_service_dirs_async().
 *
 * @param ctl The dinitctl.
 * @param[out] dirs The directories.
 * @param[out] num_dirs Number of directories.
 *
 * @return Zero on success or a positive or negative error code.
 */
DINITCTL_API int dinitctl_query_service_dirs(dinitctl *ctl, char ***dirs, size_t *num_dirs);

/** @brief Get the working directory and service dirs of dinit.
 *
 * This retrieves the current working directory of the current
 * dinit instance along with its service directories.
 *
 * This API may only fail with ENOMEM.
 *
 * @param ctl The dinitctl.
 * @param cb The callback.
 * @param data The data to pass to the callback.
 *
 * @return 0 on success, negative value on error.
 */
DINITCTL_API int dinitctl_query_service_dirs_async(dinitctl *ctl, dinitctl_async_cb cb, void *data);

/** @brief Finish getting the directories.
 *
 * The directories are written in dirs, and their number (which is the number
 * of service directories plus the current working directory) in num_dirs.
 * The first directory in the array is the current working directory, and
 * service directories follow it in priority order.
 *
 * The array must be freed with free().
 *
 * This call may fail with DINITCTL_ERROR, or with ENOMEM if the dirs
 * array allocation fails.
 *
 * @param ctl The dinitctl.
 * @param[out] dirs The directories.
 * @param[out] num_dirs Number of directories.
 *
 * @return Zero on success or non-zero on failure.
 */
DINITCTL_API int dinitctl_query_service_dirs_finish(dinitctl *ctl, char ***dirs, size_t *num_dirs);

#ifdef __cplusplus
}
#endif

#endif
