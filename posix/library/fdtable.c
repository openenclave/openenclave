// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "include/fdtable.h"
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "include/console.h"
#include "include/device.h"

/*
**==============================================================================
**
** Define an array of entry_t elements.
**
**==============================================================================
*/

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

/*
**==============================================================================
**
** Public interface:
**
**==============================================================================
*/

int oe_fdtable_assign(oe_device_t* device)
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
        retval = oe_array_resize(&_fd_arr, _table_size() + 1);

        if (retval != 0)
        {
            oe_errno = OE_ENOMEM;
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

int oe_fdtable_clear(int fd)
{
    int ret = -1;

    if (!(fd >= 0 && (size_t)fd < _table_size()))
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    oe_spin_lock(&_lock);
    _table()[fd].device = NULL;
    oe_spin_unlock(&_lock);

    ret = 0;

done:
    return ret;
}

int oe_fdtable_set(int fd, oe_device_t* device)
{
    int ret = -1;
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
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (_table()[fd].device != NULL)
    {
        oe_errno = OE_EADDRINUSE;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    _table()[fd].device = device;

    ret = 0;

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
    switch (fd)
    {
        case OE_STDIN_FILENO:
        {
            ret = oe_get_stdin_device();
            goto done;
        }
        case OE_STDOUT_FILENO:
        {
            ret = oe_get_stdout_device();
            goto done;
        }
        case OE_STDERR_FILENO:
        {
            ret = oe_get_stderr_device();
            goto done;
        }
    }

    oe_spin_unlock(&_lock);
    locked = true;

    OE_TRACE_INFO("fd=%d", fd);

    if (fd < 0 || fd >= (int)_table_size())
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_table()[fd].device == NULL)
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = _table()[fd].device;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

oe_device_t* oe_fdtable_get(int fd, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device;

    if (!(device = _get_fd_device(fd)))
        goto done;

    if (type != OE_DEVICE_TYPE_NONE && device->type != type)
        oe_errno = OE_EINVAL;

    ret = device;

done:
    return ret;
}
