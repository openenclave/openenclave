// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/posix/array.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fd.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

typedef struct _entry
{
    oe_device_t* device;
} entry_t;

#define ELEMENT_SIZE sizeof(entry_t)
#define CHUNK_SIZE 8

static oe_array_t _fd_arr = OE_ARRAY_INITIALIZER(ELEMENT_SIZE, CHUNK_SIZE);
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static bool _initialized = false;

OE_INLINE entry_t* _table(void)
{
    return (entry_t*)_fd_arr.data;
}

OE_INLINE size_t _table_size(void)
{
    return _fd_arr.size;
}

static void _free_table(void)
{
    oe_array_free(&_fd_arr);
}

static int _init_table()
{
    if (_initialized == false)
    {
        oe_spin_lock(&_lock);
        {
            if (_initialized == false)
            {
                if (oe_array_resize(&_fd_arr, CHUNK_SIZE) != 0)
                {
                    oe_assert("_init_table()" == NULL);
                    oe_abort();
                }

                oe_atexit(_free_table);
                _initialized = true;
            }
        }
        oe_spin_unlock(&_lock);
    }

    return 0;
}

int oe_assign_fd_device(oe_device_t* device)
{
    int ret = -1;
    size_t index;
    bool locked = false;

    if (_init_table() != 0)
    {
        OE_TRACE_ERROR("_init_table failed");
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    /* Search for a free slot in the file descriptor table. */
    for (index = OE_STDERR_FILENO + 1; index < _table_size(); index++)
    {
        if (!_table()[index].device)
            break;
    }

    /* If free slot not found, expand size of the file descriptor table. */
    if (index == _table_size())
    {
        int retval = -1;
        retval = oe_array_resize(&_fd_arr, _table_size() + CHUNK_SIZE);

        if (retval != 0)
        {
            oe_errno = ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }
    }

    _table()[index].device = device;
    ret = (int)index;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

void oe_release_fd(int fd)
{
    oe_spin_lock(&_lock);

    OE_TRACE_VERBOSE("oe_release_fd fd =%d", fd);
    if (fd >= 0 && (size_t)fd < _table_size())
    {
        _table()[fd].device = NULL;
    }

    oe_spin_unlock(&_lock);
}

oe_device_t* oe_set_fd_device(int fd, oe_device_t* device)
{
    oe_device_t* ret = NULL;
    bool locked = false;

    if (_init_table() != 0)
    {
        OE_TRACE_ERROR("_init_table failed");
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    if (fd < 0 || (size_t)fd >= _table_size())
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (_table()[fd].device != NULL)
    {
        oe_errno = EADDRINUSE;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    _table()[fd].device = device; // We don't clone

    ret = device;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

static oe_device_t* _get_fd_device(int fd)
{
    oe_device_t* ret = NULL;
    bool locked = false;

    /* First check whether it is a console device. */
    {
        extern oe_device_t* oe_get_console_device(int fd);
        oe_device_t* device;

        if ((device = oe_get_console_device(fd)))
            return device;
    }

    oe_spin_unlock(&_lock);
    locked = true;

    OE_TRACE_INFO("fd=%d", fd);

    if (fd < 0 || fd >= (int)_table_size())
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_table()[fd].device == NULL)
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = _table()[fd].device;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

oe_device_t* oe_get_fd_device(int fd, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device;

    if (!(device = _get_fd_device(fd)))
        goto done;

    if (type != OE_DEVICE_TYPE_NONE && device->type != type)
        oe_errno = EINVAL;

    ret = device;

done:
    return ret;
}

int oe_dup(int oldfd)
{
    oe_device_t* old_dev;
    oe_device_t* new_dev = NULL;
    int newfd = -1;
    int retval = -1;

    if (!(old_dev = oe_get_fd_device(oldfd, OE_DEVICE_TYPE_NONE)))
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("oldfd=%d oe_errno=%d", oldfd, oe_errno);
        goto done;
    }

    if ((retval = (*old_dev->ops.base->dup)(old_dev, &new_dev)) < 0)
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR(
            "oldfd=%d oe_errno=%d retval=%d", oldfd, oe_errno, retval);
        newfd = -1;
        goto done;
    }

    if (!(newfd = oe_assign_fd_device(new_dev)))
    {
        // ATTN:IO: release new_dev here.
    }

done:

    return newfd;
}

int oe_dup2(int oldfd, int newfd)
{
    oe_device_t* old_dev;
    oe_device_t* new_dev;
    oe_device_t* dev = NULL;
    int retval = -1;

    if (!(old_dev = oe_get_fd_device(oldfd, OE_DEVICE_TYPE_NONE)))
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("oldfd=%d oe_errno=%d", oldfd, oe_errno);
        goto done;
    }

    if (!(new_dev = oe_get_fd_device(newfd, OE_DEVICE_TYPE_NONE)))
    {
        (*new_dev->ops.base->close)(new_dev);
    }

    if ((retval = (*old_dev->ops.base->dup)(old_dev, &dev)) < 0)
    {
        oe_errno = EBADF;
        newfd = -1;
        goto done;
    }

    // ATTN:IO: release dev if this fails. */
    if (oe_set_fd_device(newfd, dev))
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("newfd=%d dev=%p oe_errno=%d", newfd, dev, oe_errno);
        (*dev->ops.base->close)(dev);
        newfd = -1;
        goto done;
    }

done:

    return newfd;
}
