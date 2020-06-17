// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_DEVICE_H
#define _OE_SYSCALL_DEVICE_H

#include <openenclave/bits/fs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/syscall/fd.h>
#include <openenclave/internal/syscall/sys/stat.h>

OE_EXTERNC_BEGIN

/* Device identifiers defined by Open Enclave. */
enum
{
    /* The null device id. */
    OE_DEVID_NONE,

    /* The console file system (stdin, stdout, stderr). */
    OE_DEVID_CONSOLE_FILE_SYSTEM,

    /* The non-secure host file system. */
    OE_DEVID_HOST_FILE_SYSTEM,

    /* The Intel SGX protected file system. */
    OE_DEVID_SGX_FILE_SYSTEM,

    /* The non-secure host socket device. */
    OE_DEVID_HOST_SOCKET_INTERFACE,

    /* The host epoll device. */
    OE_DEVID_HOST_EPOLL,
};

/* Device names. */
#define OE_DEVICE_NAME_CONSOLE_FILE_SYSTEM "oe_console_file_system"
#define OE_DEVICE_NAME_HOST_FILE_SYSTEM OE_HOST_FILE_SYSTEM
#define OE_DEVICE_NAME_SGX_FILE_SYSTEM OE_SGX_FILE_SYSTEM
#define OE_DEVICE_NAME_HOST_SOCKET_INTERFACE "oe_host_socket_interface"
#define OE_DEVICE_NAME_HOST_EPOLL "oe_host_epoll"

typedef enum _oe_device_type
{
    OE_DEVICE_TYPE_NONE = 0,
    OE_DEVICE_TYPE_ANY,
    OE_DEVICE_TYPE_FILE_SYSTEM,
    OE_DEVICE_TYPE_SOCKET_INTERFACE,
    OE_DEVICE_TYPE_EPOLL,
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
        const char* filesystemtype,
        unsigned long flags,
        const void* data);

    int (*umount2)(oe_device_t* fs, const char* target, int flags);

    oe_fd_t* (*open)(
        oe_device_t* fs,
        const char* pathname,
        int flags,
        oe_mode_t mode);

    int (*stat)(oe_device_t* fs, const char* pathname, struct oe_stat_t* buf);

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

typedef struct _oe_device oe_device_t;

struct _oe_device
{
    /* Type of this device. */
    oe_device_type_t type;

    /* String name of this device. */
    const char* name;

    /* Function table for this device. */
    union {
        oe_device_ops_t device;
        oe_fs_device_ops_t fs;
        oe_socket_device_ops_t socket;
        oe_epoll_device_ops_t epoll;
    } ops;
};

int oe_device_table_set(uint64_t devid, oe_device_t* dev);

oe_device_t* oe_device_table_get(uint64_t devid, oe_device_type_t type);

/* Find the device with the given name and type. */
oe_device_t* oe_device_table_find(const char* name, oe_device_type_t type);

/* Remove the given device from the table and call its release() method. */
int oe_device_table_remove(uint64_t devid);

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

#endif // _OE_SYSCALL_DEVICE_H
