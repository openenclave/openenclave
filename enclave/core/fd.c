// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/fd.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>

typedef struct _entry
{
    oe_device_t* device;
} entry_t;

static const size_t ELEMENT_SIZE = sizeof(entry_t);
static const size_t CHUNK_SIZE = 8;
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
        goto done;

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
        if (oe_array_resize(&_fd_arr, _table_size() + CHUNK_SIZE) != 0)
        {
            oe_errno = ENOMEM;
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
        goto done;

    oe_spin_lock(&_lock);
    locked = true;

    if (fd < 0 || (size_t)fd >= _table_size())
    {
        oe_errno = EBADF;
        goto done;
    }

    if (_table()[fd].device != NULL)
    {
        oe_errno = EADDRINUSE;
        goto done;
    }

    _table()[fd].device = device; // We don't clone

    ret = device;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

oe_device_t* oe_get_fd_device(int fd)
{
    oe_device_t* ret = NULL;
    bool locked = false;

    oe_spin_unlock(&_lock);
    locked = true;

    if (fd < 0 || fd >= (int)_table_size())
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (_table()[fd].device == NULL)
    {
        oe_errno = EBADF;
        goto done;
    }

    ret = _table()[fd].device;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_dup(int oldfd)
{
    oe_device_t* old_dev = oe_get_fd_device(oldfd);
    oe_device_t* new_dev = NULL;
    int newfd = -1;
    int retval = -1;

    if ((retval = (*old_dev->ops.base->dup)(old_dev, &new_dev)) < 0)
    {
        oe_errno = EBADF;
        newfd = -1;
        goto done;
    }
    newfd = oe_assign_fd_device(new_dev);

done:

    return newfd;
}

int oe_dup2(int oldfd, int newfd)
{
    oe_device_t* old_dev = oe_get_fd_device(oldfd);
    oe_device_t* old_new_dev = oe_get_fd_device(newfd);
    oe_device_t* new_dev = NULL;
    int retval = -1;

    if (old_new_dev)
    {
        (*old_new_dev->ops.base->close)(old_new_dev);
    }

    if ((retval = (*old_dev->ops.base->dup)(old_dev, &new_dev)) < 0)
    {
        oe_errno = EBADF;
        newfd = -1;
        goto done;
    }

    if (oe_set_fd_device(newfd, new_dev))
    {
        oe_errno = EBADF;
        (*new_dev->ops.base->close)(new_dev);
        newfd = -1;
        goto done;
    }

done:

    return newfd;
}
