// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_DEVICE_H
#define _OE_POSIX_DEVICE_H

#include <openenclave/bits/device.h>
#include <openenclave/bits/result.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/internal/posix/fd.h>

OE_EXTERNC_BEGIN

typedef enum _oe_device_type
{
    OE_DEVICE_TYPE_NONE = 0,
    OE_DEVICE_TYPE_ANY,
    OE_DEVICE_TYPE_FILE_SYSTEM,
    OE_DEVICE_TYPE_SOCKET_INTERFACE,
    OE_DEVICE_TYPE_EPOLL,
    OE_DEVICE_TYPE_EVENTFD,
} oe_device_type_t;

typedef struct _oe_device oe_device_t;

typedef struct _oe_device_ops
{
    int (*release)(oe_device_t* dev);

} oe_device_ops_t;

typedef struct _oe_fs_device_ops
{
    oe_device_ops_t base;

    int (*clone)(oe_device_t* device, oe_device_t** new_device);

    int (*mount)(
        oe_device_t* fs,
        const char* source,
        const char* target,
        unsigned long flags);

    int (*umount)(oe_device_t* fs, const char* target);

    oe_fd_t* (*open)(
        oe_device_t* fs,
        const char* pathname,
        int flags,
        oe_mode_t mode);

    int (*stat)(oe_device_t* fs, const char* pathname, struct oe_stat* buf);

    int (*access)(oe_device_t* fs, const char* pathname, int mode);

    int (*link)(oe_device_t* fs, const char* oldpath, const char* newpath);

    int (*unlink)(oe_device_t* fs, const char* pathname);

    int (*rename)(oe_device_t* fs, const char* oldpath, const char* newpath);

    int (*truncate)(oe_device_t* fs, const char* path, oe_off_t length);

    int (*mkdir)(oe_device_t* fs, const char* pathname, oe_mode_t mode);

    int (*rmdir)(oe_device_t* fs, const char* pathname);

} oe_fs_device_ops_t;

typedef struct _oe_socket_device_ops
{
    oe_device_ops_t base;

    oe_fd_t* (*socket)(oe_device_t* dev, int domain, int type, int protocol);

    ssize_t (*socketpair)(
        oe_device_t* dev,
        int domain,
        int type,
        int protocol,
        oe_fd_t* retdevs[2]);

} oe_socket_device_ops_t;

typedef struct _oe_epoll_device_ops
{
    oe_device_ops_t base;

    oe_fd_t* (*epoll_create)(oe_device_t* epfd_device, int size);

    oe_fd_t* (*epoll_create1)(oe_device_t* epfd_device, int flags);

} oe_epoll_device_ops_t;

typedef struct _oe_eventfd_device_ops
{
    oe_device_ops_t base;

    oe_fd_t* (*eventfd)(oe_device_t* dev, unsigned int initval, int flags);

} oe_eventfd_device_ops_t;

typedef struct _oe_device oe_device_t;

struct _oe_device
{
    /* Type of this device. */
    oe_device_type_t type;

    /* String name of this device. */
    const char* name;

    /* Function table for this device. */
    union {
        oe_device_ops_t base;
        oe_fs_device_ops_t fs;
        oe_socket_device_ops_t socket;
        oe_epoll_device_ops_t epoll;
        oe_eventfd_device_ops_t eventfd;
    } ops;
};

int oe_clear_devid(uint64_t devid);

int oe_set_device(uint64_t devid, oe_device_t* dev);

oe_device_t* oe_get_device(uint64_t devid, oe_device_type_t type);

/* Find the device with the given name and type. */
oe_device_t* oe_find_device(const char* name, oe_device_type_t type);

int oe_remove_device(uint64_t devid);

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
