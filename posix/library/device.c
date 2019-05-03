// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/bits/device.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

#include "include/device.h"

/*
**=============================================================================
**
** Define an array of pointers to devices.
**
**=============================================================================
*/

#define ELEMENT_SIZE (sizeof(oe_device_t*))
#define CHUNK_SIZE ((size_t)8)

static oe_array_t _dev_arr = OE_ARRAY_INITIALIZER(ELEMENT_SIZE, CHUNK_SIZE);
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static bool _initialized = false;

OE_INLINE oe_device_t** _table(void)
{
    return (oe_device_t**)_dev_arr.data;
}

OE_INLINE size_t _table_size(void)
{
    return _dev_arr.size;
}

static void _free_table(void)
{
    oe_array_free(&_dev_arr);
}

static int _init_table()
{
    if (_initialized == false)
    {
        oe_spin_lock(&_lock);
        {
            if (_initialized == false)
            {
                if (oe_array_resize(&_dev_arr, CHUNK_SIZE) != 0)
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
**=============================================================================
**
** Public interface
**
**=============================================================================
*/

uint64_t oe_allocate_devid(uint64_t devid)
{
    uint64_t ret = OE_DEVID_NONE;
    bool locked = false;

    if (!_initialized && _init_table() != 0)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= _dev_arr.size)
    {
        if (oe_array_resize(&_dev_arr, devid + 1) != 0)
        {
            oe_errno = OE_ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }
    }

    if (_table()[devid] != NULL)
    {
        oe_errno = OE_EADDRINUSE;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    ret = devid;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_release_devid(uint64_t devid)
{
    int ret = -1;
    bool locked = false;

    if (!_initialized && _init_table() != 0)
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= _dev_arr.size || _table()[devid] == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    _table()[devid] = NULL;

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_set_devid_device(uint64_t devid, oe_device_t* device)
{
    int ret = -1;

    if (devid > _table_size())
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (_table()[devid] != NULL)
    {
        oe_errno = OE_EADDRINUSE;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    _table()[devid] = device;

    ret = 0;

done:
    return ret;
}

oe_device_t* oe_get_device(uint64_t devid, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device;

    if (devid >= _table_size())
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    device = _table()[devid];

    if (device && type != OE_DEVICE_TYPE_NONE && device->type != type)
        goto done;

    ret = device;

done:
    return ret;
}

int oe_remove_device(uint64_t devid)
{
    int ret = -1;
    int retval = -1;
    oe_device_t* device;

    if (!(device = oe_get_device(devid, OE_DEVICE_TYPE_NONE)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("no device found: devid=%lu", devid);
        goto done;
    }

    if (device->ops.base->shutdown == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if ((retval = (*device->ops.base->shutdown)(device)) != 0)
    {
        OE_TRACE_ERROR("devid=%lu retval=%d", devid, retval);
        goto done;
    }

    ret = 0;

done:
    return ret;
}

uint64_t oe_device_name_to_devid(const char* name)
{
    uint64_t ret = OE_DEVID_NONE;

    if (!name)
        goto done;

    for (uint64_t devid = 0; devid < (uint64_t)_table_size(); devid++)
    {
        oe_device_t* dev = _table()[devid];

        if (dev && oe_strcmp(dev->name, name) == 0)
        {
            ret = devid;
            goto done;
        }
    }

done:
    return ret;
}

/*
**==============================================================================
**
** oe_set_device_for_current_thread()
** oe_get_device_for_current_thread()
** oe_clear_device_for_current_thread()
**
**==============================================================================
*/

static oe_once_t _tls_device_once = OE_ONCE_INIT;
static oe_thread_key_t _tls_device_key = OE_THREADKEY_INITIALIZER;

static void _create_tls_device_key()
{
    if (oe_thread_key_create(&_tls_device_key, NULL) != 0)
        oe_abort();
}

oe_result_t oe_set_device_for_current_thread(const char* device_name)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t devid;

    if ((devid = oe_device_name_to_devid(device_name)) == OE_DEVID_NONE)
    {
        OE_TRACE_ERROR("no such device: %s", device_name);
        result = OE_NOT_FOUND;
        goto done;
    }

    if (oe_once(&_tls_device_once, _create_tls_device_key) != OE_OK)
    {
        OE_TRACE_ERROR("devid=%lu result=%s", devid, oe_result_str(result));
        result = OE_FAILURE;
        goto done;
    }

    if (oe_thread_setspecific(_tls_device_key, (void*)devid) != OE_OK)
    {
        OE_TRACE_ERROR("devid=%lu result=%s", devid, oe_result_str(result));
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_clear_device_for_current_thread(void)
{
    oe_result_t result = OE_UNEXPECTED;

    if (oe_once(&_tls_device_once, _create_tls_device_key) != OE_OK)
    {
        OE_TRACE_ERROR("%s", oe_result_str(result));
        result = OE_FAILURE;
        goto done;
    }

    if (oe_thread_setspecific(_tls_device_key, NULL) != OE_OK)
    {
        OE_TRACE_ERROR("%s", oe_result_str(result));
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}

uint64_t oe_get_device_for_current_thread(void)
{
    uint64_t ret = OE_DEVID_NONE;
    uint64_t devid;

    if (oe_once(&_tls_device_once, _create_tls_device_key) != 0)
        goto done;

    if (!(devid = (uint64_t)oe_thread_getspecific(_tls_device_key)))
        goto done;

    ret = devid;

done:
    return ret;
}
