// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_DEVICE_H
#define _OE_POSIX_DEVICE_H

#include <openenclave/bits/device.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/posix/epollops.h>
#include <openenclave/internal/posix/eventfdops.h>
#include <openenclave/internal/posix/fsops.h>
#include <openenclave/internal/posix/sockops.h>

OE_EXTERNC_BEGIN

typedef enum _oe_device_type
{
    OE_DEVICE_TYPE_NONE = 0,
    OE_DEVICE_TYPE_ANY,
    OE_DEVICE_TYPE_FILESYSTEM,
    OE_DEVICE_TYPE_DIRECTORY,
    OE_DEVICE_TYPE_FILE,
    OE_DEVICE_TYPE_SOCKET,
    OE_DEVICE_TYPE_EPOLL,
    OE_DEVICE_TYPE_EVENTFD,
} oe_device_type_t;

typedef struct _oe_device oe_device_t;

struct _oe_device
{
    /* Type of this device. */
    oe_device_type_t type;

    /* String name of this device. */
    const char* name;

    /* Function table for this device. */
    union {
        oe_device_ops_t* base;
        oe_fs_ops_t* fs;
        oe_sock_ops_t* sock;
        oe_epoll_ops_t* epoll;
        oe_eventfd_ops_t* eventfd;
    } ops;
};

int oe_clear_devid(uint64_t devid);

int oe_set_device(uint64_t devid, oe_device_t* dev);

oe_device_t* oe_get_device(uint64_t devid, oe_device_type_t type);

/* Find the device with the given name and type. */
oe_device_t* oe_find_device(const char* name, oe_device_type_t type);

int oe_remove_device(uint64_t devid);

// clang-format off
#define __OE_CALL(OPS, FUNC, DEV, ...)                                  \
    ({                                                                  \
        oe_device_t* __dev__ = DEV;                                     \
        if (!__dev__ || !__dev__->ops.OPS || !__dev__->ops.OPS->FUNC)   \
        {                                                               \
            oe_errno = OE_EINVAL;                                       \
            goto done;                                                  \
        }                                                               \
        (*__dev__->ops.OPS->FUNC)(__dev__, ##__VA_ARGS__);              \
    })                                                                  \
// clang-format on

#define OE_CALL_BASE(FUNC, DEV, ...) __OE_CALL(base, FUNC, DEV, ##__VA_ARGS__)

#define OE_CALL_FS(FUNC, DEV, ...) __OE_CALL(fs, FUNC, DEV, ##__VA_ARGS__)

#define OE_CALL_SOCK(FUNC, DEV, ...) __OE_CALL(sock, FUNC, DEV, ##__VA_ARGS__)

#define OE_CALL_EPOLL(FUNC, DEV, ...) __OE_CALL(epoll, FUNC, DEV, ##__VA_ARGS__)

#define OE_CALL_EVENTFD(FUNC, DEV, ...) \
    __OE_CALL(eventfd, FUNC, DEV, ##__VA_ARGS__)

/**
 * Associate a device id with the current thread.
 *
 * This function associates the given device id with the current thread.
 * It sets this device id into a thread-local-storage slot, which affects
 * the behaviour of the following libc functions:
 *
 *     - open()
 *     - rename()
 *     - access()
 *     - truncate()
 *     - link()
 *     - unlink()
 *     - rmdir()
 *     - opendir()
 *     - stat()
 *     - mkdir()
 *     - socket()
 *
 * By default, these functions use either the mounter (file I/O) or the
 * address family (socket I/O) to select a device for the given operation.
 * But this function bypasses these device resolution methods and uses the
 * device given by the **devid** parameter (for the calling thread).
 *
 * The following example shows how to open a file using the Intel Protected
 * file system (SGXFS).
 *
 *     ```
 *     oe_set_thread_devid(OE_DEVID_SGX_FILE_SYSTEM);
 *
 *     int fd = open(pathname, flags, mode);
 *
 *     oe_clear_thread_devid(OE_DEVID_SGX_FILE_SYSTEM);
 *     ```
 *
 * After the operation is performed, the thread should clear the device id
 * for the current thread by calling **oe_clear_thread_devid()**.
 *
 * Applications may define helper functions that encapsulate this interaction.
 * For example:
 *
 *     ```
 *     int open_sgxfs(const char *pathname, int flags, mode_t mode)
 *     {
 *         if (oe_set_thread_devid(OE_DEVID_SGX_FILE_SYSTEM) != OE_OK)
 *         {
 *             errno = EINVAL;
 *             return -1;
 *         }
 *
 *         int fd = open(pathname, flags, mode);
 *
 *         if (oe_clear_thread_devid(OE_DEVID_SGX_FILE_SYSTEM) != OE_OK)
 *         {
 *             errno = EINVAL;
 *             return -1;
 *         }
 *
 *         return fd;
 *     }
 *     ```
 *
 * @param devid the device id to be associated with the current thread.
 *
 * @return OE_OK success
 * @return OE_FAILURE failure
 */
oe_result_t oe_set_thread_devid(uint64_t devid);

/**
 * Disassociate the device id from the current thread.
 *
 * This function severs the association between the device id and the current
 * thread that was established with **oe_set_thread_devid()**. After calling
 * this function, **oe_get_thread_devid()** returns **OE_DEVID_NONE**.
 *
 * @return OE_OK success
 * @return OE_FAILURE failure
 */
oe_result_t oe_clear_thread_devid(void);

/**
 * Return the device id associated with the current thread.
 *
 * This function returns the device id associated with the current thread
 * that was established with **oe_set_thread_devid()**.
 *
 * @returns the device id or **OE_DEVID_NONE** none currently associated.
 */
uint64_t oe_get_thread_devid(void);

OE_EXTERNC_END

#endif // _OE_POSIX_DEVICE_H
