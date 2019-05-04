// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/bits/device.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

#include "device.h"

#define MAX_TABLE_SIZE 128

static oe_device_t* _table[MAX_TABLE_SIZE];
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

uint64_t oe_allocate_devid(uint64_t devid)
{
    uint64_t ret = OE_DEVID_NONE;
    bool locked = false;

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= MAX_TABLE_SIZE)
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (_table[devid] != NULL)
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

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= MAX_TABLE_SIZE || _table[devid] == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    _table[devid] = NULL;

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_set_device(uint64_t devid, oe_device_t* device)
{
    int ret = -1;

    if (devid > MAX_TABLE_SIZE)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (_table[devid] != NULL)
    {
        oe_errno = OE_EADDRINUSE;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    _table[devid] = device;

    ret = 0;

done:
    return ret;
}

oe_device_t* oe_get_device(uint64_t devid, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device;

    if (devid >= MAX_TABLE_SIZE)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    device = _table[devid];

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

/*
**==============================================================================
**
** oe_set_thread_devid()
** oe_get_thread_devid()
** oe_clear_thread_devid()
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

oe_result_t oe_set_thread_devid(uint64_t devid)
{
    oe_result_t result = OE_UNEXPECTED;

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

oe_result_t oe_clear_thread_devid(void)
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

uint64_t oe_get_thread_devid(void)
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
