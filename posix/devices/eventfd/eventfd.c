// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/eventfdops.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/posix/fd.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/eventfd.h>
#include <openenclave/bits/module.h>
#include <openenclave/internal/trace.h>

/*
**==============================================================================
**
** eventfd operations:
**
**==============================================================================
*/

#define MAX_EVENTFD_COUNT 0xfffffffffffffffe
#define DEVICE_MAGIC 0x4e455645
#define EVENTFD_MAGIC 0x87aada8f

static oe_eventfd_operations_t _get_eventfd_operations(void);

typedef struct _device
{
    struct _oe_device base;
    uint32_t magic;
} device_t;

typedef struct _eventfd
{
    oe_fd_t base;
    uint32_t magic;
    uint64_t count;
    uint32_t flags;
    oe_cond_t waitfor; // blocked on by read and set by write
} eventfd_t;

static device_t* _cast_device(const oe_device_t* device)
{
    device_t* p = (device_t*)device;

    if (p == NULL || p->magic != DEVICE_MAGIC)
        return NULL;

    return p;
}

static eventfd_t* _cast_eventfd(const oe_fd_t* desc)
{
    eventfd_t* p = (eventfd_t*)desc;

    if (p == NULL || p->magic != EVENTFD_MAGIC)
        return NULL;

    return p;
}

static device_t _eventfd;

static int _eventfd_close(oe_fd_t*);

static oe_fd_t* _eventfd_eventfd(
    oe_device_t* eventfd_,
    unsigned int initval,
    int flags)
{
    oe_fd_t* ret = NULL;
    device_t* eventfd = _cast_device(eventfd_);
    eventfd_t* new_eventfd = NULL;

    if (!eventfd)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(new_eventfd = oe_calloc(1, sizeof(eventfd_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    new_eventfd->base.type = OE_DEVID_EVENTFD;
    new_eventfd->magic = EVENTFD_MAGIC;
    new_eventfd->base.ops.eventfd = _get_eventfd_operations();
    new_eventfd->count = initval;
    new_eventfd->flags = (uint32_t)flags;

done:
    return ret;
}

static ssize_t _eventfd_read(oe_fd_t* eventfd_, void* buf, size_t count)
{
    ssize_t ret = -1;
    eventfd_t* eventfd = _cast_eventfd(eventfd_);

    oe_errno = 0;

    /* Check parameters. */
    if (!eventfd || !buf || (count < sizeof(uint64_t)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!eventfd->count)
    {
        if (eventfd->flags & OE_EFD_NONBLOCK)
            OE_RAISE_ERRNO(OE_EAGAIN);
    }

    if (eventfd->flags & OE_EFD_SEMAPHORE)
    {
        if (oe_memcpy_s(buf, count, &eventfd->count, sizeof(uint64_t)) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        eventfd->count = 0;
        ret = sizeof(uint64_t);
    }
    else
    {
        static const uint64_t one = 1;

        if (oe_memcpy_s(buf, count, &one, sizeof(uint64_t)) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        eventfd->count--;
        ret = sizeof(uint64_t);
    }

done:
    return ret;
}

static ssize_t _eventfd_write(oe_fd_t* eventfd_, const void* buf, size_t count)
{
    ssize_t ret = -1;
    eventfd_t* eventfd = _cast_eventfd(eventfd_);
    uint64_t incr = 0;
    __uint128_t total;

    oe_errno = 0;

    /* Check parameters. */
    if (!eventfd || !buf || (count < sizeof(uint64_t)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (eventfd->count >= MAX_EVENTFD_COUNT)
    {
        if (eventfd->flags & OE_EFD_NONBLOCK)
            OE_RAISE_ERRNO(OE_EAGAIN);
    }

    if (oe_memcpy_s(&incr, sizeof(incr), buf, sizeof(uint64_t)) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    total = (__uint128_t)eventfd->count + (__uint128_t)incr;
    if (total > MAX_EVENTFD_COUNT)
    {
        eventfd->count = MAX_EVENTFD_COUNT;
    }
    else
    {
        eventfd->count += incr;
    }

    ret = 8;

done:
    return ret;
}

static int _eventfd_ioctl(
    oe_fd_t* eventfd_,
    unsigned long request,
    uint64_t arg)
{
    OE_UNUSED(eventfd_);
    OE_UNUSED(request);
    OE_UNUSED(arg);
    OE_RAISE_ERRNO(OE_ENOTSUP);

done:
    return -1;
}

static int _eventfd_close(oe_fd_t* eventfd_)
{
    int ret = -1;
    eventfd_t* eventfd = _cast_eventfd(eventfd_);

    oe_errno = 0;

    /* Check parameters. */
    if (!eventfd)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Release the eventfd_ object. */
    oe_free(eventfd);

    ret = 0;

done:
    return ret;
}

static int _eventfd_release(oe_device_t* eventfd_)
{
    int ret = -1;
    device_t* eventfd = _cast_device(eventfd_);

    oe_errno = 0;

    if (!eventfd)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_free(eventfd);

    ret = 0;

done:
    return ret;
}

static oe_host_fd_t _eventfd_gethostfd(oe_fd_t* eventfd_)
{
    OE_UNUSED(eventfd_);
    OE_RAISE_ERRNO(OE_ENOTSUP);

done:
    return -1;
}

static oe_eventfd_operations_t _eventfd_operations = {
    .base.ioctl = _eventfd_ioctl,
    .base.read = _eventfd_read,
    .base.write = _eventfd_write,
    .base.close = _eventfd_close,
    .base.get_host_fd = _eventfd_gethostfd,
};

static oe_eventfd_operations_t _get_eventfd_operations()
{
    return _eventfd_operations;
};

static oe_eventfd_device_ops_t _ops = {
    .base.release = _eventfd_release,
    .eventfd = _eventfd_eventfd,
};

static device_t _eventfd = {
    .base.type = OE_DEVID_EVENTFD,
    .base.name = OE_DEVICE_NAME_EVENTFD,
    .base.ops.eventfd = &_ops,
    .magic = DEVICE_MAGIC,
};

static oe_once_t _once = OE_ONCE_INITIALIZER;
static bool _loaded;

static void _load_once(void)
{
    oe_result_t result = OE_FAILURE;
    const uint64_t devid = OE_DEVID_EVENTFD;

    if (oe_set_device(devid, &_eventfd.base) != 0)
        OE_RAISE_ERRNO(oe_errno);

    result = OE_OK;

done:

    if (result == OE_OK)
        _loaded = true;
}

oe_result_t oe_load_module_eventfd(void)
{
    if (oe_once(&_once, _load_once) != OE_OK || !_loaded)
        return OE_FAILURE;

    return OE_OK;
}
