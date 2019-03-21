// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/device.h>
#include <openenclave/internal/eventfd_ops.h>
#include <openenclave/internal/eventfd.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/hostbatch.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
//#include "../common/eventfdargs.h"

void* memcpy(void* to, const void* from, size_t size);
/*
**==============================================================================
**
** host batch:
**
**==============================================================================
*/

#if 0
static void _atexit_handler()
{
}
#endif

/*
**==============================================================================
**
** eventfd operations:
**
**==============================================================================
*/

#define EVENTFD_MAGIC 0x4e455645

typedef struct _eventfd
{
    struct _oe_device base;
    uint32_t magic;
    uint64_t ready_mask;
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
        goto done;
    }

    if (!(new_eventfd = oe_calloc(1, sizeof(eventfd_dev_t))))
    {
        oe_errno = ENOMEM;
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
        goto done;
    }

    oe_free(eventfd);
    ret = 0;

done:
    return ret;
}

static oe_device_t* _eventfd_eventfd(
    oe_device_t* eventfd_,
    uint64_t initval,
    int flags)
{
    oe_device_t* ret = NULL;
    eventfd_dev_t* eventfd = NULL;

    (void)_eventfd_clone(eventfd_, &ret);
    eventfd = _cast_eventfd(ret);
    if (!eventfd)
    {
        oe_errno = EINVAL;
        goto done;
    }
    else
    {
        eventfd->base.type = OE_DEVID_EVENTFD;
        eventfd->base.size = sizeof(eventfd_dev_t);
        eventfd->magic = EVENTFD_MAGIC;
        eventfd->base.ops.eventfd = _eventfd.base.ops.eventfd;
        eventfd->count = initval;
        eventfd->flags = (uint32_t)flags;
    }

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
        goto done;
    }

    if (!eventfd->count)
    {
        if (eventfd->flags & OE_EFD_NONBLOCK)
        {
            oe_errno = EAGAIN;
            return -1;
        }
        else
        {
            // Block on condition variable
            // Then proceed
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
        const static uint64_t one = 1;
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

    oe_errno = 0;

    /* Check parameters. */
    if (!eventfd || !buf || (count < sizeof(uint64_t)))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (eventfd->count >= 0xfffffffffffffffe)
    {
        if (eventfd->flags & OE_EFD_NONBLOCK)
        {
            oe_errno = EAGAIN;
            return -1;
        }
        else
        {
            // signal condition variable
        }
    }

    uint64_t incr = 0;
    memcpy(&incr, buf, sizeof(uint64_t));

    __uint128_t total = (__uint128_t)eventfd->count + (__uint128_t)incr;
    if (total > 0xfffffffffffffffe)
    {
        eventfd->count = 0xfffffffffffffffe;
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
    if (!eventfd_)
    {
        oe_errno = EINVAL;
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

    /* Check parameters. */
    if (!eventfd_)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Release the eventfd_ object. */
    oe_free(eventfd);

    ret = 0;

done:
    return ret;
}

static int _eventfd_notify(oe_device_t* eventfd_, uint64_t notification_mask)
{
    eventfd_dev_t* eventfd = _cast_eventfd(eventfd_);

    if (eventfd->ready_mask != notification_mask)
    {
        // We notify any eventfds in progress.
    }
    eventfd->ready_mask = notification_mask;
    return 0;
}

static ssize_t _eventfd_gethostfd(oe_device_t* eventfd_)
{
    (void)eventfd_;
    return -1;
}

static uint64_t _eventfd_readystate(oe_device_t* eventfd_)
{
    eventfd_dev_t* eventfd = _cast_eventfd(eventfd_);
    return eventfd->ready_mask;
}

static oe_eventfd_ops_t _ops = {
    .base.clone = _eventfd_clone,
    .base.release = _eventfd_release,
    .base.ioctl = NULL,
    .base.read = _eventfd_read,
    .base.write = _eventfd_write,
    .base.close = _eventfd_close,
    .base.notify = _eventfd_notify,
    .base.get_host_fd = _eventfd_gethostfd,
    .base.ready_state = _eventfd_readystate,
    .base.shutdown = _eventfd_shutdown_device,
    .eventfd = _eventfd_eventfd,
};

static eventfd_dev_t _eventfd = {
    .base.type = OE_DEVID_EVENTFD,
    .base.size = sizeof(eventfd_dev_t),
    .base.ops.eventfd = &_ops,
    .magic = EVENTFD_MAGIC,
    .ready_mask = 0,
    .count = 0,
    .flags = 0,
    .waitfor = OE_COND_INITIALIZER,
};

oe_device_t* oe_get_eventfd_device(void)
{
    return &_eventfd.base;
}
