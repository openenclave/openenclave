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
#include "console.h"

/*
**==============================================================================
**
** Define the table of file-descriptor entries:
**
**==============================================================================
*/

/* The table allocation grows in multiples of the chunk size. */
#define TABLE_CHUNK_SIZE 1024

typedef struct _entry entry_t;

struct _entry
{
    entry_t* prev;
    entry_t* next;
    bool is_on_list;
    oe_device_t* device;
};

typedef struct _entry_list
{
    entry_t* head;
    entry_t* tail;
} list_t;

static entry_t* _table;
static size_t _table_size;
static size_t _next = OE_STDERR_FILENO + 1;
static list_t _free_list;
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

    /* The fdtable cannot be bigger than the maximum int file descriptor. */
    if (new_size > OE_INT_MAX)
        goto done;

    if (oe_once(&_once, _install_atexit_handler_once) != OE_OK)
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

static void _list_remove(list_t* list, entry_t* entry)
{
    if (entry->prev)
        entry->prev->next = entry->next;
    else
        list->head = entry->next;

    if (entry->next)
        entry->next->prev = entry->prev;
    else
        list->tail = entry->prev;

    entry->prev = NULL;
    entry->next = NULL;
    entry->is_on_list = true;
}

static void _list_prepend(list_t* list, entry_t* entry)
{
    if (list->head)
    {
        entry->prev = NULL;
        entry->next = list->head;
        list->head->prev = entry;
        list->head = entry;
    }
    else
    {
        entry->next = NULL;
        entry->prev = NULL;
        list->head = entry;
        list->tail = entry;
    }

    entry->is_on_list = true;
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
    entry_t* entry;

    oe_spin_lock(&_lock);
    locked = true;

    if (!device)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Reserve space for stdin, stdout, and stderr on the first call. */
    if (_table_size < OE_STDERR_FILENO + 1)
    {
        if (_resize_table(OE_STDERR_FILENO + 1) != 0)
        {
            oe_errno = OE_ENOMEM;
            goto done;
        }
    }

    /* Get an entry either from the free list or from the table. */
    if (_free_list.head)
    {
        entry = _free_list.head;
        _list_remove(&_free_list, entry);
    }
    else
    {
        if (_next == _table_size && _resize_table(_next + 1) != 0)
            OE_RAISE_ERRNO(OE_ENOMEM);

        entry = &_table[_next++];
    }

    /* Initialize the entry. */
    entry->device = device;

    /* Set the file descriptor return value. */
    ret = (int)(entry - _table);

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_fdtable_release(int fd)
{
    int ret = -1;
    bool locked = true;
    entry_t* entry;

    oe_spin_lock(&_lock);
    locked = true;

    /* Fail if fd is out of range. */
    if (!(fd >= 0 && (size_t)fd < _table_size))
        OE_RAISE_ERRNO(OE_EBADF);

    /* Set a pointer to the entry. */
    entry = &_table[fd];

    /* Fail if entry was never assigned. */
    if (!entry->device)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if the entry is on the free list. */
    if (entry->is_on_list)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Clear the entry and add it to the beginning of the free list. */
    entry->device = NULL;
    _list_prepend(&_free_list, entry);

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
    entry_t* entry;

    oe_spin_lock(&_lock);
    locked = true;

    if (fd < 0 || (size_t)fd >= _table_size)
        OE_RAISE_ERRNO(OE_EBADF);

    /* Set a pointer to the entry. */
    entry = &_table[fd];

    /* If the entry is on the free list. Else it is in use. */
    if (entry->is_on_list)
    {
        _list_remove(&_free_list, entry);
        oe_assert(entry->device == NULL);
    }
    else
    {
        oe_assert(entry->device != NULL);

        if ((ret = OE_CALL_BASE(close, device)) != 0)
        {
            oe_assert(entry->device == NULL);
            OE_RAISE_ERRNO(oe_errno);
        }

        entry->device = NULL;
    }

    /* Set the device. */
    entry->device = device;

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

    if (_table[fd].device == NULL)
        OE_RAISE_ERRNO(OE_EBADF);

    ret = _table[fd].device;

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
