// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEVICE_H
#define _OE_BITS_DEVICE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Device identifiers known by Open Enclave.
 */
enum
{
    /** The null device id. */
    OE_DEVID_NONE,

    /** The non-secure host file system. */
    OE_DEVID_HOSTFS,

    /** The Intel SGX protected file system. */
    OE_DEVID_SGXFS,

    /** The non-secure host socket device. */
    OE_DEVID_HOSTSOCK,

    /** The host epoll device. */
    OE_DEVID_HOSTEPOLL,

    /** The host eventfd device. */
    OE_DEVID_EVENTFD,
};

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
 *     oe_set_thread_devid(OE_DEVID_SGXFS);
 *
 *     int fd = open(pathname, flags, mode);
 *
 *     oe_clear_thread_devid(OE_DEVID_SGXFS);
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
 *         if (oe_set_thread_devid(OE_DEVID_SGXFS) != OE_OK)
 *         {
 *             errno = EINVAL;
 *             return -1;
 *         }
 *
 *         int fd = open(pathname, flags, mode);
 *
 *         if (oe_clear_thread_devid(OE_DEVID_SGXFS) != OE_OK)
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

#endif // _OE_BITS_DEVICE_H
