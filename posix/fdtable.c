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
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>

/*
**==============================================================================
**
** Define the table of file-descriptor entries:
**
**==============================================================================
*/

/* The table allocation grows in multiples of the chunk size. */
#define TABLE_CHUNK_SIZE 1024

typedef oe_device_t* entry_t;

static entry_t* _table;
static size_t _table_size;
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static bool _installed_atexit_handler;

static void _atexit_handler(void)
{
    oe_free(_table);
}

static int _resize_table(size_t new_size)
{
    int ret = -1;

    /* Install the atexit handler on the first call. */
    if (!_installed_atexit_handler)
    {
        oe_atexit(_atexit_handler);
        _installed_atexit_handler = true;
    }

    /* The fdtable cannot be bigger than the maximum int file descriptor. */
    if (new_size > OE_INT_MAX)
        goto done;

    /* Round the new capacity up to the next multiple of the chunk size. */
    new_size = oe_round_up_to_multiple(new_size, TABLE_CHUNK_SIZE);

    if (new_size > OE_INT_MAX)
        new_size = OE_INT_MAX;

    if (new_size > _table_size)
    {
        entry_t* p;
        size_t n = new_size;

        /* Reallocate the table. */
        if (!(p = oe_realloc(_table, n * sizeof(entry_t))))
            goto done;

        /* Zero-fill the unused porition. */
        memset(p + _table_size, 0, (n - _table_size) * sizeof(entry_t));

        _table = p;
        _table_size = new_size;
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
    bool locked = false;
    size_t index;

    oe_spin_lock(&_lock);
    locked = true;

    if (!device)
        OE_RAISE_ERRNO(OE_EINVAL);

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

int oe_fdtable_release(int fd)
{
    int ret = -1;
    bool locked = true;

    oe_spin_lock(&_lock);
    locked = true;

    /* Fail if fd is out of range. */
    if (!(fd >= 0 && (size_t)fd < _table_size))
        OE_RAISE_ERRNO(OE_EBADF);

    /* Fail if entry was never assigned. */
    if (!_table[fd])
        OE_RAISE_ERRNO(OE_EINVAL);

    _table[fd] = NULL;

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_fdtable_reassign(int fd, oe_device_t* device)
{
    int ret = -1;
    bool locked = false;

    oe_spin_lock(&_lock);
    locked = true;

    _resize_table(TABLE_CHUNK_SIZE);

    if (fd < 0 || (size_t)fd >= _table_size)
        OE_RAISE_ERRNO(OE_EBADF);

    if (_table[fd])
    {
        if (OE_CALL_BASE(close, _table[fd]) != 0)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Set the device. */
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
