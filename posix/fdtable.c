// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/reserve.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "console.h"

/*
**==============================================================================
**
** Define the table of oe_device_t* elements.
**
**==============================================================================
*/

#define MIN_TABLE_SIZE 256

static oe_device_t** _table;
static size_t _table_size;
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static oe_once_t _once = OE_ONCE_INITIALIZER;

static void _free_table(void)
{
    oe_free(_table);
}

static void _install_atexit_handler_once(void)
{
    oe_atexit(_free_table);
}

static int _resize_table(size_t new_size)
{
    int ret = -1;
    size_t new_capacity;

    if (oe_once(&_once, _install_atexit_handler_once) != OE_OK)
        goto done;

    new_capacity = (new_size < MIN_TABLE_SIZE) ? MIN_TABLE_SIZE : new_size;

    if (oe_reserve(
            (void**)&_table,
            _table_size,
            sizeof(oe_device_t*),
            &_table_size,
            new_capacity) != 0)
    {
        goto done;
    }

    ret = 0;

done:
    return ret;
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

    oe_spin_lock(&_lock);
    locked = true;

    if (_resize_table(OE_STDERR_FILENO + 1) != 0)
    {
        oe_errno = OE_ENOMEM;
        goto done;
    }

    /* Search for a free slot in the file descriptor table. */
    for (index = OE_STDERR_FILENO + 1; index < _table_size; index++)
    {
        if (!_table[index])
            break;
    }

    /* If free slot not found, expand size of the file descriptor table. */
    if (index == _table_size)
    {
        if (_resize_table(_table_size + 1) != 0)
            OE_RAISE_ERRNO(OE_ENOMEM);
    }

    _table[index] = device;
    ret = (int)index;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_fdtable_clear(int fd)
{
    int ret = -1;

    if (!(fd >= 0 && (size_t)fd < _table_size))
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    oe_spin_lock(&_lock);
    _table[fd] = NULL;
    oe_spin_unlock(&_lock);

    ret = 0;

done:
    return ret;
}

int oe_fdtable_set(int fd, oe_device_t* device)
{
    int ret = -1;
    bool locked = false;

    oe_spin_lock(&_lock);
    locked = true;

    if (fd < 0 || (size_t)fd >= _table_size)
        OE_RAISE_ERRNO(OE_EBADF);

    if (_table[fd] != NULL)
        OE_RAISE_ERRNO(OE_EADDRINUSE);

    _table[fd] = device;

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

    oe_spin_lock(&_lock);
    locked = true;

    if (fd < 0 || fd >= (int)_table_size)
        OE_RAISE_ERRNO(OE_EBADF);

    if (_table[fd] == NULL)
        OE_RAISE_ERRNO(OE_EBADF);

    ret = _table[fd];

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
