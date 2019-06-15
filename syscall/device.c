// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/raise.h>
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

#define TABLE_CHUNK_SIZE 64

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

    if (!_installed_atexit_handler)
    {
        oe_atexit(_atexit_handler);
        _installed_atexit_handler = true;
    }

    /* Round the new capacity up to the next multiple of the chunk size. */
    new_size = oe_round_up_to_multiple(new_size, TABLE_CHUNK_SIZE);

    if (new_size > _table_size)
    {
        entry_t* p;
        size_t n = new_size;

        /* Reallocate the table. */
        if (!(p = oe_realloc(_table, n * sizeof(entry_t))))
            goto done;

        /* Zero-fill the unused portion. */
        {
            const size_t num_bytes = (n - _table_size) * sizeof(entry_t);

            if (oe_memset_s(p + _table_size, num_bytes, 0, num_bytes) != OE_OK)
                goto done;
        }

        _table = p;
        _table_size = new_size;
    }

    ret = 0;

done:
    return ret;
}

#if !defined(NDEBUG)
static void _assert_device(oe_device_t* device)
{
    oe_assert(device->ops.device.release);

    switch (device->type)
    {
        case OE_DEVICE_TYPE_NONE:
        case OE_DEVICE_TYPE_ANY:
        {
            break;
        }
        case OE_DEVICE_TYPE_FILE_SYSTEM:
        {
            oe_assert(device->ops.fs.clone);
            oe_assert(device->ops.fs.mount);
            oe_assert(device->ops.fs.umount2);
            oe_assert(device->ops.fs.open);
            oe_assert(device->ops.fs.stat);
            oe_assert(device->ops.fs.access);
            oe_assert(device->ops.fs.link);
            oe_assert(device->ops.fs.unlink);
            oe_assert(device->ops.fs.rename);
            oe_assert(device->ops.fs.truncate);
            oe_assert(device->ops.fs.mkdir);
            oe_assert(device->ops.fs.rmdir);
            break;
        }
        case OE_DEVICE_TYPE_SOCKET_INTERFACE:
        {
            oe_assert(device->ops.socket.socket);
            oe_assert(device->ops.socket.socketpair);
            break;
        }
        default:
        {
            oe_assert(false);
            break;
        }
    }
}
#endif /* !defined(NDEBUG) */

/*
**==============================================================================
**
** Public functions:
**
**==============================================================================
*/

int oe_device_table_set(uint64_t devid, oe_device_t* device)
{
    int ret = -1;
    bool locked = false;

    if (!device)
        OE_RAISE_ERRNO(OE_EINVAL);

#if !defined(NDEBUG)
    _assert_device(device);
#endif

    oe_spin_lock(&_lock);
    locked = true;

    if (_resize_table(devid + 1) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    if (_table[devid] != NULL)
        OE_RAISE_ERRNO(OE_EEXIST);

    _table[devid] = device;

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

static oe_device_t* _get_device(uint64_t devid, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device;

    if (devid == OE_DEVID_NONE || devid >= _table_size)
        OE_RAISE_ERRNO(OE_EINVAL);

    device = _table[devid];

    if (device && type != OE_DEVICE_TYPE_ANY && device->type != type)
        goto done;

    ret = device;

done:

    return ret;
}

oe_device_t* oe_device_table_get(uint64_t devid, oe_device_type_t type)
{
    oe_device_t* ret;

    oe_spin_lock(&_lock);
    ret = _get_device(devid, type);
    oe_spin_unlock(&_lock);

    return ret;
}

oe_device_t* oe_device_table_find(const char* name, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device = NULL;
    size_t i;
    bool locked = false;

    if (!name)
        goto done;

    oe_spin_lock(&_lock);
    locked = true;

    for (i = 0; i < _table_size; i++)
    {
        oe_device_t* p = _table[i];

        if (p && oe_strcmp(p->name, name) == 0)
        {
            device = p;
            break;
        }
    }

    if (device && type != OE_DEVICE_TYPE_ANY && device->type != type)
        goto done;

    ret = device;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_device_table_remove(uint64_t devid)
{
    int ret = -1;
    oe_device_t* device;
    bool locked = false;

    oe_spin_lock(&_lock);
    locked = true;

    if (!(device = _get_device(devid, OE_DEVICE_TYPE_ANY)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (devid >= _table_size || _table[devid] == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    _table[devid] = NULL;

    if (locked)
    {
        oe_spin_unlock(&_lock);
        locked = false;
    }

    if (device->ops.device.release(device) != 0)
        OE_RAISE_ERRNO(oe_errno);

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

/*
**==============================================================================
**
** oe_set_thread_devid()
** oe_get_thread_devid()
** oe_clear_thread_devid()
**
**==============================================================================
*/

static OE_THREAD_LOCAL_STORAGE uint64_t _devid;

oe_result_t oe_set_thread_devid(uint64_t devid)
{
    _devid = devid;
    return OE_OK;
}

oe_result_t oe_clear_thread_devid(void)
{
    _devid = 0;
    return OE_OK;
}

uint64_t oe_get_thread_devid(void)
{
    return _devid;
}
