// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/posix/epollops.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/reserve.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "posix_t.h"

#define DEVICE_NAME "hostepoll"
#define EPOLL_MAGIC 0x4504f4c
#define MIN_MAP_SIZE 64

/* epoll_ctl(OE_EPOLL_CTL_ADD) establishes this pair. */
typedef struct _pair
{
    /* The fd parameter from epoll_ctl(). */
    int fd;

    /* The event parameter from epoll_ctl(). */
    struct oe_epoll_event event;
} pair_t;

typedef struct _epoll
{
    struct _oe_device base;
    uint32_t magic;
    oe_host_fd_t host_fd;

    /* Mappings added by epoll_ctl(OE_EPOLL_CTL_ADD) */
    pair_t* map;
    size_t map_size;
    size_t map_capacity;

} epoll_t;

static int _map_reserve(epoll_t* epoll, size_t new_capacity)
{
    if (new_capacity < MIN_MAP_SIZE)
        new_capacity = MIN_MAP_SIZE;

    return oe_reserve(
        (void**)&epoll->map,
        epoll->map_size,
        sizeof(pair_t),
        &epoll->map_capacity,
        new_capacity);
}

static const pair_t* _map_find(epoll_t* epoll, int fd)
{
    for (size_t i = 0; i < epoll->map_size; i++)
    {
        const pair_t* pair = &epoll->map[i];

        if (pair->fd == fd)
            return pair;
    }

    /* Not found */
    return NULL;
}

static epoll_t* _cast_epoll(const oe_device_t* device)
{
    epoll_t* epoll = (epoll_t*)device;

    if (epoll == NULL || epoll->magic != EPOLL_MAGIC)
        return NULL;

    return epoll;
}

static epoll_t _epoll;

static int _epoll_close(oe_device_t*);

static int _epoll_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    epoll_t* epoll = NULL;
    epoll_t* new_epoll = NULL;

    if (!(epoll = _cast_epoll(device)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* ATTN: need to clone map! */

    if (!(new_epoll = oe_calloc(1, sizeof(epoll_t))))
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    memcpy(new_epoll, epoll, sizeof(epoll_t));

    *new_device = &new_epoll->base;
    ret = 0;

done:
    return ret;
}

static int _epoll_release(oe_device_t* device)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(device);

    if (!epoll)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_free(epoll);
    ret = 0;

done:
    return ret;
}

static oe_device_t* _epoll_create(oe_device_t* epoll_, int size)
{
    oe_device_t* ret = NULL;
    oe_host_fd_t retval;
    epoll_t* epoll = NULL;
    oe_result_t result = OE_FAILURE;

    OE_UNUSED(size);

    oe_errno = 0;

    (void)_epoll_clone(epoll_, &ret);
    epoll = _cast_epoll(ret);

    if ((result = oe_posix_epoll_create1_ocall(&retval, 0)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("%s", oe_result_str(result));
        goto done;
    }

    if (retval != -1)
    {
        epoll->base.type = OE_DEVID_HOSTEPOLL;
        epoll->base.name = DEVICE_NAME;
        epoll->magic = EPOLL_MAGIC;
        epoll->base.ops.epoll = _epoll.base.ops.epoll;
        epoll->host_fd = retval;
    }

done:
    return ret;
}

static oe_device_t* _epoll_create1(oe_device_t* epoll_, int32_t flags)
{
    oe_device_t* ret = NULL;
    epoll_t* epoll = NULL;
    oe_host_fd_t retval;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    (void)_epoll_clone(epoll_, &ret);
    epoll = _cast_epoll(ret);

    if ((result = oe_posix_epoll_create1_ocall(&retval, flags)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("%s", oe_result_str(result));
        goto done;
    }

    if (retval != -1)
    {
        epoll->base.type = OE_DEVID_HOSTEPOLL;
        epoll->base.name = DEVICE_NAME;
        epoll->magic = EPOLL_MAGIC;
        epoll->base.ops.epoll = _epoll.base.ops.epoll;
        epoll->host_fd = retval;
    }

done:
    return ret;
}

static int _epoll_ctl_add(epoll_t* epoll, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_device_t* dev = oe_fdtable_get(fd, OE_DEVICE_TYPE_NONE);
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    struct oe_epoll_event host_event;
    int retval;

    oe_errno = 0;

    /* Check parameters. */
    if (!epoll || !dev || !event)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Get the host fd for the epoll device. */
    host_epfd = epoll->host_fd;

    /* Get the host fd for the device. */
    if ((host_fd = OE_CALL_BASE(get_host_fd, dev)) == -1)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Initialize the host event. */
    {
        memset(&host_event, 0, sizeof(host_event));
        host_event.events = event->events;
        host_event.data.fd = fd;
    }

    if (oe_posix_epoll_ctl_ocall(
            &retval, host_epfd, OE_EPOLL_CTL_ADD, host_fd, &host_event) !=
        OE_OK)
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Add the new pair. */
    {
        if (_map_reserve(epoll, epoll->map_size + 1) != 0)
            goto done;

        epoll->map[epoll->map_size].fd = fd;
        epoll->map[epoll->map_size].event = *event;
        epoll->map_size++;
    }

    ret = 0;

done:
    return ret;
}

static int _epoll_ctl_mod(epoll_t* epoll, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_device_t* dev = oe_fdtable_get(fd, OE_DEVICE_TYPE_NONE);
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    struct oe_epoll_event host_event;
    int retval;

    oe_errno = 0;

    /* Check parameters. */
    if (!epoll || !dev || !event)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Get the host fd for the epoll device. */
    host_epfd = epoll->host_fd;

    /* Get the host fd for the device. */
    {
        if ((host_fd = OE_CALL_BASE(get_host_fd, dev)) == -1)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }
    }

    /* Initialize the host event. */
    {
        memset(&host_event, 0, sizeof(host_event));
        host_event.events = event->events;
        host_event.data.fd = fd;
    }

    if (oe_posix_epoll_ctl_ocall(
            &retval, host_epfd, OE_EPOLL_CTL_MOD, host_fd, &host_event) !=
        OE_OK)
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Modify the pair. */
    {
        bool found = false;

        for (size_t i = 0; epoll->map_size; i++)
        {
            if (epoll->map[i].fd == fd)
            {
                epoll->map[i].event = *event;
                found = true;
                break;
            }
        }

        if (!found)
        {
            oe_errno = OE_ENOENT;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }
    }

    ret = 0;

done:
    return ret;
}

static int _epoll_ctl_del(epoll_t* epoll, int fd)
{
    int ret = -1;
    oe_device_t* dev = oe_fdtable_get(fd, OE_DEVICE_TYPE_NONE);
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    int retval;

    oe_errno = 0;

    /* Check parameters. */
    if (!epoll || !dev)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Get the host fd for the epoll device. */
    host_epfd = epoll->host_fd;

    /* Get the host fd for the device. */
    {
        if ((host_fd = OE_CALL_BASE(get_host_fd, dev)) == -1)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }
    }

    if (oe_posix_epoll_ctl_ocall(
            &retval, host_epfd, OE_EPOLL_CTL_DEL, host_fd, NULL) != OE_OK)
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Delete the pair. */
    {
        bool found = false;

        for (size_t i = 0; epoll->map_size; i++)
        {
            if (epoll->map[i].fd == fd)
            {
                /* Swap with last element of array. */
                epoll->map[i] = epoll->map[--epoll->map_size];
                found = true;
                break;
            }
        }

        if (!found)
        {
            oe_errno = OE_ENOENT;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }
    }

    ret = 0;

done:
    return ret;
}

static int _epoll_ctl(
    oe_device_t* device,
    int op,
    int fd,
    struct oe_epoll_event* event)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(device);

    if (!epoll)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    switch (op)
    {
        case OE_EPOLL_CTL_ADD:
            return _epoll_ctl_add(epoll, fd, event);

        case OE_EPOLL_CTL_MOD:
            return _epoll_ctl_mod(epoll, fd, event);

        case OE_EPOLL_CTL_DEL:
            return _epoll_ctl_del(epoll, fd);

        default:
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            return -1;
        }
    }

    ret = 0;

done:
    return ret;
}

static int _epoll_wait(
    oe_device_t* device,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout)
{
    int ret = -1;
    int retval;
    epoll_t* epoll = _cast_epoll(device);
    oe_host_fd_t host_epfd = -1;

    if (!epoll || !events || maxevents <= 0)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = 0;

    host_epfd = OE_CALL_BASE(get_host_fd, (oe_device_t*)epoll);
    if (host_epfd == -1)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (oe_posix_epoll_wait_ocall(
            &retval, host_epfd, events, (unsigned int)maxevents, timeout) !=
        OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (retval > 0)
    {
        if (retval > maxevents)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        for (int i = 0; i < retval; i++)
        {
            struct oe_epoll_event* event = &events[i];
            const pair_t* pair;

            if (!(pair = _map_find(epoll, event->data.fd)))
            {
                oe_errno = OE_ENOENT;
                OE_TRACE_ERROR("oe_errno=%d", oe_errno);
                goto done;
            }

            event->data.u64 = pair->event.data.u64;
        }
    }

    ret = (int)retval;

done:

    return ret;
}

static int _epoll_close(oe_device_t* epoll_)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);
    int retval = -1;

    oe_errno = 0;

    if (!epoll)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Close the file descriptor on the host side. */
    if (oe_posix_epoll_close_ocall(&retval, epoll->host_fd) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (retval != 0)
    {
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (epoll->map)
        oe_free(epoll->map);

    oe_free(epoll);

    ret = 0;

done:
    return ret;
}

static int _epoll_shutdown_device(oe_device_t* epoll_)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);

    oe_errno = 0;

    if (!epoll)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Release the epoll_ object. */
    oe_free(epoll);

    ret = 0;

done:
    return ret;
}

static oe_host_fd_t _epoll_gethostfd(oe_device_t* epoll_)
{
    epoll_t* epoll = _cast_epoll(epoll_);
    return epoll->host_fd;
}

static oe_epoll_ops_t _ops = {
    .base.clone = _epoll_clone,
    .base.release = _epoll_release,
    .base.ioctl = NULL,
    .base.read = NULL,
    .base.write = NULL,
    .base.close = _epoll_close,
    .base.get_host_fd = _epoll_gethostfd,
    .base.shutdown = _epoll_shutdown_device,
    .epoll_create = _epoll_create,
    .epoll_create1 = _epoll_create1,
    .epoll_ctl = _epoll_ctl,
    .epoll_wait = _epoll_wait,
};

static epoll_t _epoll = {
    .base.type = OE_DEVID_HOSTEPOLL,
    .base.name = DEVICE_NAME,
    .base.ops.epoll = &_ops,
    .magic = EPOLL_MAGIC,
};

static oe_once_t _once = OE_ONCE_INITIALIZER;
static bool _loaded;

static void _load_once(void)
{
    oe_result_t result = OE_FAILURE;
    const uint64_t devid = OE_DEVID_HOSTEPOLL;

    if (oe_set_device(devid, &_epoll.base) != 0)
    {
        OE_TRACE_ERROR("devid=%lu ", devid);
        goto done;
    }

    result = OE_OK;

done:

    if (result == OE_OK)
        _loaded = true;
}

oe_result_t oe_load_module_hostepoll(void)
{
    if (oe_once(&_once, _load_once) != OE_OK || !_loaded)
        return OE_FAILURE;

    return OE_OK;
}
