// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

#define MAX_TABLE_SIZE 128

static oe_device_t* _table[MAX_TABLE_SIZE];
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

int oe_clear_devid(uint64_t devid)
{
    int ret = -1;
    bool locked = false;

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= MAX_TABLE_SIZE || _table[devid] == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

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

    oe_spin_lock(&_lock);

    if (devid > MAX_TABLE_SIZE)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (_table[devid] != NULL)
        OE_RAISE_ERRNO(OE_EADDRINUSE);

    _table[devid] = device;

    ret = 0;

done:
    oe_spin_unlock(&_lock);

    return ret;
}

oe_device_t* oe_get_device(uint64_t devid, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device;

    oe_spin_lock(&_lock);

    if (devid >= MAX_TABLE_SIZE)
        OE_RAISE_ERRNO(OE_EINVAL);

    device = _table[devid];

    if (device && type != OE_DEVICE_TYPE_NONE && device->type != type)
        goto done;

    ret = device;

done:
    oe_spin_unlock(&_lock);

    return ret;
}

oe_device_t* oe_find_device(const char* name, oe_device_type_t type)
{
    oe_device_t* ret = NULL;
    oe_device_t* device = NULL;
    size_t i;

    oe_spin_lock(&_lock);

    if (!name)
        goto done;

    for (i = 0; i < MAX_TABLE_SIZE; i++)
    {
        oe_device_t* p = _table[i];

        if (p && oe_strcmp(p->name, name) == 0)
        {
            device = p;
            break;
        }
    }

    if (device && type != OE_DEVICE_TYPE_NONE && device->type != type)
        goto done;

    ret = device;

done:
    oe_spin_unlock(&_lock);

    return ret;
}

int oe_remove_device(uint64_t devid)
{
    int ret = -1;
    int retval = -1;
    oe_device_t* device;

    if (!(device = oe_get_device(devid, OE_DEVICE_TYPE_NONE)))
        OE_RAISE_ERRNO(OE_EINVAL);

    OE_CALL_BASE(shutdown, device);

    if ((retval = OE_CALL_BASE(shutdown, device)) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_clear_devid(devid) != 0)
        OE_RAISE_ERRNO(oe_errno);

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

    OE_CHECK(oe_once(&_tls_device_once, _create_tls_device_key));

    OE_CHECK(oe_thread_setspecific(_tls_device_key, (void*)devid));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_clear_thread_devid(void)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_CHECK(oe_once(&_tls_device_once, _create_tls_device_key));

    OE_CHECK((oe_thread_setspecific(_tls_device_key, NULL)));

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
