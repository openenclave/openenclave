// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/eventfd_ops.h>
#include <openenclave/internal/posix/eventfd.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/bits/module.h>
#include <openenclave/internal/trace.h>

/*
**==============================================================================
**
** eventfd operations:
**
**==============================================================================
*/

#define DEVICE_NAME "eventfd"
#define MAX_EVENTFD_COUNT 0xfffffffffffffffe
#define EVENTFD_MAGIC 0x4e455645

typedef struct _eventfd
{
    struct _oe_device base;
    uint32_t magic;
    uint64_t count;
    uint32_t flags;
    oe_cond_t waitfor; // blocked on by read and set by write
} eventfd_dev_t;

static eventfd_dev_t* _cast_eventfd(const oe_device_t* device)
{
    eventfd_dev_t* eventfd = (eventfd_dev_t*)device;

    if (eventfd == NULL || eventfd->magic != EVENTFD_MAGIC)
        return NULL;

    return eventfd;
}

static eventfd_dev_t _eventfd;

static int _eventfd_close(oe_device_t*);

static int _eventfd_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    eventfd_dev_t* eventfd = _cast_eventfd(device);
    eventfd_dev_t* new_eventfd = NULL;

    if (!eventfd || !new_device)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    new_eventfd = oe_calloc(1, sizeof(eventfd_dev_t));

    if (!new_eventfd)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    memcpy(new_eventfd, eventfd, sizeof(eventfd_dev_t));

    *new_device = &new_eventfd->base;
    ret = 0;

done:
    return ret;
}

static int _eventfd_release(oe_device_t* device)
{
    int ret = -1;
    eventfd_dev_t* eventfd = _cast_eventfd(device);

    if (!eventfd)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_free(eventfd);
    ret = 0;

done:
    return ret;
}

static oe_device_t* _eventfd_eventfd(
    oe_device_t* eventfd_,
    unsigned int initval,
    int flags)
{
    oe_device_t* ret = NULL;
    eventfd_dev_t* eventfd = _cast_eventfd(eventfd_);
    eventfd_dev_t* new_eventfd = NULL;

    if (!eventfd)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_eventfd_clone(eventfd_, (oe_device_t**)&new_eventfd) != 0)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    new_eventfd->base.type = OE_DEVID_EVENTFD;
    new_eventfd->base.name = DEVICE_NAME;
    new_eventfd->magic = EVENTFD_MAGIC;
    new_eventfd->base.ops.eventfd = _eventfd.base.ops.eventfd;
    new_eventfd->count = initval;
    new_eventfd->flags = (uint32_t)flags;

done:
    return ret;
}

static ssize_t _eventfd_read(oe_device_t* eventfd_, void* buf, size_t count)
{
    ssize_t ret = -1;
    eventfd_dev_t* eventfd = _cast_eventfd(eventfd_);

    oe_errno = 0;

    /* Check parameters. */
    if (!eventfd || !buf || (count < sizeof(uint64_t)))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (!eventfd->count)
    {
        if (eventfd->flags & OE_EFD_NONBLOCK)
        {
            oe_errno = EAGAIN;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }
    }

    if (eventfd->flags & OE_EFD_SEMAPHORE)
    {
        memcpy(buf, &eventfd->count, sizeof(uint64_t));
        eventfd->count = 0;
        ret = 8; //? man page isn't clear
    }
    else
    {
        static const uint64_t one = 1;
        memcpy(buf, &one, sizeof(uint64_t));
        eventfd->count--;
        ret = 8; //? man page isn't clear
    }

done:
    return ret;
}

static ssize_t _eventfd_write(
    oe_device_t* eventfd_,
    const void* buf,
    size_t count)
{
    ssize_t ret = -1;
    eventfd_dev_t* eventfd = _cast_eventfd(eventfd_);
    uint64_t incr = 0;
    __uint128_t total;

    oe_errno = 0;

    /* Check parameters. */
    if (!eventfd || !buf || (count < sizeof(uint64_t)))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (eventfd->count >= MAX_EVENTFD_COUNT)
    {
        if (eventfd->flags & OE_EFD_NONBLOCK)
        {
            oe_errno = EAGAIN;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }

        {
            // signal condition variable
        }
    }

    memcpy(&incr, buf, sizeof(uint64_t));

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

static int _eventfd_close(oe_device_t* eventfd_)
{
    int ret = -1;
    eventfd_dev_t* eventfd = _cast_eventfd(eventfd_);

    oe_errno = 0;

    /* Check parameters. */
    if (!eventfd)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    /* Release the eventfd_ object. */
    oe_free(eventfd);

    ret = 0;

done:
    return ret;
}

static int _eventfd_shutdown_device(oe_device_t* eventfd_)
{
    int ret = -1;
    eventfd_dev_t* eventfd = _cast_eventfd(eventfd_);

    oe_errno = 0;

    if (!eventfd)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_free(eventfd);

    ret = 0;

done:
    return ret;
}

static ssize_t _eventfd_gethostfd(oe_device_t* eventfd_)
{
    (void)eventfd_;
    return -1;
}

static oe_eventfd_ops_t _ops = {
    .base.clone = _eventfd_clone,
    .base.release = _eventfd_release,
    .base.ioctl = NULL,
    .base.read = _eventfd_read,
    .base.write = _eventfd_write,
    .base.close = _eventfd_close,
    .base.get_host_fd = _eventfd_gethostfd,
    .base.shutdown = _eventfd_shutdown_device,
    .eventfd = _eventfd_eventfd,
};

static eventfd_dev_t _eventfd = {
    .base.type = OE_DEVID_EVENTFD,
    .base.name = DEVICE_NAME,
    .base.ops.eventfd = &_ops,
    .magic = EVENTFD_MAGIC,
    .count = 0,
    .flags = 0,
    .waitfor = OE_COND_INITIALIZER,
};

oe_device_t* oe_get_eventfd_device(void)
{
    return &_eventfd.base;
}

oe_result_t oe_load_module_eventfd(void)
{
    oe_result_t result = OE_FAILURE;
    static bool _loaded = false;
    int ret = -1;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

    if (!_loaded)
    {
        oe_spin_lock(&_lock);

        if (!_loaded)
        {
            const uint64_t devid = OE_DEVID_EVENTFD;

            if (oe_allocate_devid(devid) != devid)
            {
                OE_TRACE_ERROR("devid=%lu", devid);
                goto done;
            }

            if ((ret = oe_set_devid_device(devid, oe_get_eventfd_device())) !=
                0)
            {
                OE_TRACE_ERROR("devid=%lu ret=%d", devid, ret);
                goto done;
            }
            _loaded = true;
        }
        oe_spin_unlock(&_lock);
    }

    result = OE_OK;

done:
    return result;
}
