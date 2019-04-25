// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/epoll_ops.h>
#include <openenclave/internal/posix/epoll.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/posix/epoll.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/bits/module.h>
#include <openenclave/internal/trace.h>
#include "oe_t.h"

/*
**==============================================================================
**
** epoll operations:
**
**==============================================================================
*/

#define DEVICE_NAME "hostepoll"

#define EPOLL_MAGIC 0x4504f4c

typedef struct _epoll_event_data
{
    int64_t enclave_fd;
    uint64_t enclave_data;
} epoll_event_data_t;

typedef struct _epoll
{
    struct _oe_device base;
    uint32_t magic;
    int64_t host_fd;
    uint64_t ready_mask;
    size_t max_event_data;
    size_t num_event_data;
    epoll_event_data_t* pevent_data;
} epoll_dev_t;

#define EVENT_DATA_LIST_BUMP 16

static epoll_dev_t* _cast_epoll(const oe_device_t* device)
{
    epoll_dev_t* epoll = (epoll_dev_t*)device;

    if (epoll == NULL || epoll->magic != EPOLL_MAGIC)
        return NULL;

    return epoll;
}

static epoll_event_data_t* add_event_data(
    struct _epoll* pepoll,
    epoll_event_data_t* pevent,
    int* list_idx)
{
    size_t idx = 0;
    if (!pepoll || !pevent)
    {
        return NULL;
    }

    if (pepoll->pevent_data == NULL)
    {
        pepoll->max_event_data = EVENT_DATA_LIST_BUMP;
        pepoll->num_event_data = 0;
        pepoll->pevent_data =
            oe_calloc(1, sizeof(epoll_event_data_t) * pepoll->max_event_data);
        if (pepoll->pevent_data == NULL)
        {
            return NULL;
        }
    }

    // num_event_data is the top of the array used descriptors, but there might
    // have been deleted entries; when we delete an entry we invalidate, but
    // because the list index is our key from the host, we need to keep all the
    // other entries where the are. So when we go to add an entry we loop
    // through the list and use any deleted entries before adding.
    for (idx = 0; idx < pepoll->num_event_data; idx++)
    {
        if (pepoll->pevent_data[idx].enclave_fd == -1)
        {
            break;
        }
    }

    // assert that idx <= num_event_data
    if (idx >= pepoll->max_event_data)
    {
        epoll_event_data_t* ptr;

        // If we passed into here, idx == num_event_data indicating no empty
        // slots and num_event_data. so open a slot
        idx = pepoll->num_event_data++;
        pepoll->max_event_data += EVENT_DATA_LIST_BUMP;

        ptr = oe_realloc(
            pepoll->pevent_data,
            sizeof(epoll_event_data_t) * pepoll->max_event_data);

        if (!ptr)
            return NULL;

        pepoll->pevent_data = ptr;
    }
    else
    {
        // idx could be less than max but  equal than num
        if (idx >= pepoll->num_event_data)
        {
            idx = pepoll->num_event_data++;
        }
    }
    pepoll->pevent_data[idx] = *pevent;
    *list_idx = (int)idx;

    return pepoll->pevent_data;
}

static epoll_event_data_t* delete_event_data(
    struct _epoll* pepoll,
    int enclave_fd)
{
    size_t idx = 0;

    if (!pepoll)
    {
        return NULL;
    }

    if (pepoll->pevent_data == NULL)
    {
        return NULL;
    }

    for (idx = 0; idx < pepoll->num_event_data; idx++)
    {
        if (pepoll->pevent_data[idx].enclave_fd == enclave_fd)
        {
            break;
        }
    }

    if (idx >= pepoll->num_event_data)
    {
        return NULL;
    }
    pepoll->pevent_data[idx].enclave_fd = -1;
    pepoll->pevent_data[idx].enclave_data = 0;

    return pepoll->pevent_data;
}

static epoll_event_data_t* modify_event_data(
    struct _epoll* pepoll,
    epoll_event_data_t* pevent)
{
    size_t idx = 0;

    if (!pepoll || !pevent)
    {
        return NULL;
    }

    if (pepoll->pevent_data == NULL)
    {
        return NULL;
    }

    for (idx = 0; idx < pepoll->num_event_data; idx++)
    {
        if (pepoll->pevent_data[idx].enclave_fd == pevent->enclave_fd)
        {
            break;
        }
    }

    if (idx >= pepoll->num_event_data)
    {
        return NULL;
    }
    pepoll->pevent_data[idx].enclave_fd = pevent->enclave_fd;
    pepoll->pevent_data[idx].enclave_data = pevent->enclave_data;

    return pepoll->pevent_data;
}

static epoll_dev_t _epoll;

static int _epoll_close(oe_device_t*);

static int _epoll_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    epoll_dev_t* epoll = NULL;
    epoll_dev_t* new_epoll = NULL;

    if (!(epoll = _cast_epoll(device)))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (!(new_epoll = oe_calloc(1, sizeof(epoll_dev_t))))
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    memcpy(new_epoll, epoll, sizeof(epoll_dev_t));

    *new_device = &new_epoll->base;
    ret = 0;

done:
    return ret;
}

static int _epoll_release(oe_device_t* device)
{
    int ret = -1;
    epoll_dev_t* epoll = NULL;

    if (!(epoll = _cast_epoll(device)))
    {
        oe_errno = EINVAL;
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
    int retval;
    epoll_dev_t* epoll = NULL;
    oe_result_t result = OE_FAILURE;

    OE_UNUSED(size);

    oe_errno = 0;

    (void)_epoll_clone(epoll_, &ret);
    epoll = _cast_epoll(ret);

    if ((result = oe_posix_epoll_create1_ocall(&retval, 0, &oe_errno)) != OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("%s", oe_result_str(result));
        goto done;
    }

    if (retval != -1)
    {
        epoll->base.type = OE_DEVID_EPOLL;
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
    epoll_dev_t* epoll = NULL;
    int retval;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    (void)_epoll_clone(epoll_, &ret);
    epoll = _cast_epoll(ret);

    if ((result = oe_posix_epoll_create1_ocall(&retval, flags, &oe_errno)) !=
        OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("%s", oe_result_str(result));
        goto done;
    }

    if (retval != -1)
    {
        epoll->base.type = OE_DEVID_EPOLL;
        epoll->base.name = DEVICE_NAME;
        epoll->magic = EPOLL_MAGIC;
        epoll->base.ops.epoll = _epoll.base.ops.epoll;
        epoll->host_fd = retval;
    }

done:
    return ret;
}

static int _epoll_ctl_add(
    int epoll_fd,
    int enclave_fd,
    struct oe_epoll_event* event)
{
    int ret = -1;
    epoll_dev_t* epoll =
        _cast_epoll(oe_get_fd_device(epoll_fd, OE_DEVICE_TYPE_EPOLL));
    ssize_t host_fd = -1;
    oe_device_t* pdev = oe_get_fd_device(enclave_fd, OE_DEVICE_TYPE_NONE);
    int list_idx = -1;
    epoll_event_data_t ev_data = {0};

    /* Check parameters. */
    if (!epoll || !pdev || !event || (enclave_fd == -1))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = 0;
    if (pdev->ops.base->get_host_fd != NULL)
    {
        host_fd = (*pdev->ops.base->get_host_fd)(pdev);
    }

    if (host_fd == -1)
    {
        // Not a host file system. Skip the ocall
        return 0;
    }

    ev_data.enclave_fd = enclave_fd;
    ev_data.enclave_data = event->data.u64;

    if (add_event_data(epoll, &ev_data, &list_idx) == NULL)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (oe_posix_epoll_ctl_add_ocall(
            &ret,
            (int)epoll->host_fd,
            (int)host_fd,
            event->events,
            list_idx,
            epoll_fd,
            &oe_errno) != OE_OK)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

done:
    return ret;
}

/* ATTN:IO: add test for mod case. */
static int _epoll_ctl_mod(
    int epoll_fd,
    int enclave_fd,
    struct oe_epoll_event* event)
{
    int ret = -1;
    epoll_dev_t* epoll =
        _cast_epoll(oe_get_fd_device(epoll_fd, OE_DEVICE_TYPE_EPOLL));
    ssize_t host_fd = -1;
    oe_device_t* pdev = oe_get_fd_device(enclave_fd, OE_DEVICE_TYPE_NONE);
    oe_result_t result = OE_FAILURE;
    epoll_event_data_t ev_data = {0};

    if (!epoll || !pdev || !event)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = 0;
    if (pdev->ops.base->get_host_fd != NULL)
    {
        host_fd = (*pdev->ops.base->get_host_fd)(pdev);
    }

    if (host_fd == -1)
    {
        // Not a host file system. Skip the ocall
        return 0;
    }

    ev_data.enclave_fd = enclave_fd;
    ev_data.enclave_data = event->data.u64;

    if (modify_event_data(epoll, &ev_data) == NULL)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_epoll_ctl_mod_ocall(
             &ret,
             (int)epoll->host_fd,
             (int)host_fd,
             event->events,
             enclave_fd,
             epoll_fd,
             &oe_errno)) != OE_OK)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR(
            "epoll->host_fd=%ld host_fd=%ld %s oe_errno =%d ",
            epoll->host_fd,
            host_fd,
            oe_result_str(result),
            oe_errno);
        goto done;
    }

done:
    return ret;
}

/* ATTN:IO: add test for del case. */
static int _epoll_ctl_del(int epoll_fd, int enclave_fd)
{
    int ret = -1;
    epoll_dev_t* epoll =
        _cast_epoll(oe_get_fd_device(epoll_fd, OE_DEVICE_TYPE_EPOLL));
    ssize_t host_fd = -1;
    oe_device_t* pdev = oe_get_fd_device(enclave_fd, OE_DEVICE_TYPE_NONE);
    oe_result_t result = OE_FAILURE;

    /* Check parameters. */
    if (!epoll || !pdev)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = 0;
    if (pdev->ops.base->get_host_fd != NULL)
    {
        host_fd = (*pdev->ops.base->get_host_fd)(pdev);
    }

    if (host_fd == -1)
    {
        // Not a host file system. Skip the ocall
        return 0;
    }

    if (delete_event_data(epoll, enclave_fd) == NULL)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_epoll_ctl_del_ocall(
             &ret, (int)epoll->host_fd, (int)host_fd, &oe_errno)) != OE_OK)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR(
            "epoll->host_fd=%ld host_fd=%ld %s oe_errno =%d ",
            epoll->host_fd,
            host_fd,
            oe_result_str(result),
            oe_errno);
        goto done;
    }

done:
    return ret;
}

static int _epoll_wait(
    int epoll_fd,
    struct oe_epoll_event* events,
    size_t maxevents,
    int64_t timeout)
{
    int ret = -1;
    epoll_dev_t* epoll =
        _cast_epoll(oe_get_fd_device(epoll_fd, OE_DEVICE_TYPE_EPOLL));
    ssize_t epoll_host_fd = -1;
    struct oe_epoll_event* host_events = NULL;
    oe_result_t result = OE_FAILURE;

    // ATTN:IO: timeout is unused.
    OE_UNUSED(timeout);

    if (!epoll || !events)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = 0;

    if (epoll->base.ops.base->get_host_fd != NULL)
    {
        epoll_host_fd =
            (*epoll->base.ops.base->get_host_fd)((oe_device_t*)epoll);
    }

    if (epoll_host_fd == -1)
    {
        // Not a host file system. Skip the ocall
        return 0;
    }

    host_events = oe_calloc(1, sizeof(struct oe_epoll_event) * maxevents);
    if (!host_events)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    result = oe_posix_epoll_wait_async_ocall(
        &ret,
        (int64_t)oe_get_enclave(),
        (int)epoll_host_fd,
        maxevents,
        &oe_errno);
    if (result != OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (ret != -1)
    {
        size_t i;

        for (i = 0; ((int)i < ret) && (i < maxevents); i++)
        {
            oe_ev_data_t data;
            int list_idx;

            data.data = host_events[i].data.u64;
            list_idx = (int)data.event_list_idx;
            events[i].events = host_events[i].events;
            events[i].data.u64 = epoll->pevent_data[list_idx].enclave_data;
        }
    }

done:

    if (host_events)
        oe_free(host_events);

    return ret;
}

static int _epoll_add_event_data(
    int epoll_fd,
    int enclave_fd,
    uint32_t events,
    uint64_t data)
{
    int ret = -1;
    epoll_dev_t* epoll =
        _cast_epoll(oe_get_fd_device(epoll_fd, OE_DEVICE_TYPE_EPOLL));
    oe_device_t* pdev = oe_get_fd_device(enclave_fd, OE_DEVICE_TYPE_NONE);
    epoll_event_data_t ev_data = {};
    int list_idx = -1;

    OE_UNUSED(events);

    if (!epoll || !pdev || (enclave_fd == -1))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = 0;

    ev_data.enclave_fd = enclave_fd;
    ev_data.enclave_data = data;

    if (add_event_data(epoll, &ev_data, &list_idx) == NULL)
    {
        oe_errno = ENOMEM;
        goto done;
    }
    ret = 0;

done:
    return ret;
}

static int _epoll_poll(
    int epoll_fd,
    struct oe_pollfd* fds,
    size_t nfds,
    int64_t timeout)
{
    int ret = -1;
    epoll_dev_t* epoll =
        _cast_epoll(oe_get_fd_device(epoll_fd, OE_DEVICE_TYPE_EPOLL));
    oe_device_t* pdev = NULL;
    struct oe_pollfd* host_fds = NULL;
    oe_result_t result = OE_FAILURE;

    if (!epoll || !fds)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = 0;

    if (nfds > 0)
    {
        if (!(host_fds = oe_calloc(1, sizeof(struct oe_pollfd) * nfds)))
        {
            oe_errno = ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        size_t fd_idx = 0;
        for (; fd_idx < nfds; fd_idx++)
        {
            int host_fd = -1;
            pdev = oe_get_fd_device(fds[fd_idx].fd, OE_DEVICE_TYPE_NONE);
            if (pdev)
            {
                if (pdev->ops.base->get_host_fd != NULL)
                {
                    host_fd = (int)(*pdev->ops.base->get_host_fd)(pdev);
                }
            }
            host_fds[fd_idx].fd =
                host_fd; // -1 will be ignored by poll on the host side. 2do:
                         // how to poll enclave local
            host_fds[fd_idx].events = fds[fd_idx].events;
            host_fds[fd_idx].revents = 0;
        }
    }

    result = oe_posix_epoll_poll_ocall(
        &ret,
        (int64_t)oe_get_enclave(),
        (int)epoll_fd,
        host_fds,
        nfds,
        (int)timeout,
        &oe_errno);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(
            "epoll_fd=%d host_fds=%p result=%s oe_errno=%d",
            epoll_fd,
            host_fds,
            oe_result_str(result),
            oe_errno);
        goto done;
    }

done:
    if (host_fds)
    {
        oe_free(host_fds);
    }
    return ret;
}

static int _epoll_close(oe_device_t* epoll_)
{
    int ret = -1;
    epoll_dev_t* epoll = _cast_epoll(epoll_);

    oe_errno = 0;

    if (!epoll)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (epoll->pevent_data)
    {
        oe_free(epoll->pevent_data);
    }

    /* Release the epoll_ object. */
    oe_free(epoll);

    ret = 0;

done:
    return ret;
}

static int _epoll_shutdown_device(oe_device_t* epoll_)
{
    int ret = -1;
    epoll_dev_t* epoll = _cast_epoll(epoll_);

    oe_errno = 0;

    if (!epoll)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Release the epoll_ object. */
    oe_free(epoll);

    ret = 0;

done:
    return ret;
}

static uint64_t _epoll_get_event_data(oe_device_t* epoll_, uint32_t list_idx)
{
    epoll_dev_t* epoll = _cast_epoll(epoll_);
    uint64_t ret = (uint64_t)-1;

    if (!epoll)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (list_idx > epoll->num_event_data)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (!epoll->pevent_data)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = epoll->pevent_data[list_idx].enclave_data;
done:
    return ret;
}

static ssize_t _epoll_gethostfd(oe_device_t* epoll_)
{
    epoll_dev_t* epoll = _cast_epoll(epoll_);
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
    .create = _epoll_create,
    .create1 = _epoll_create1,
    .ctl_add = _epoll_ctl_add,
    .ctl_mod = _epoll_ctl_mod,
    .ctl_del = _epoll_ctl_del,
    .add_event_data = _epoll_add_event_data,
    .get_event_data = _epoll_get_event_data,
    .wait = _epoll_wait,
    .poll = _epoll_poll,
};

static epoll_dev_t _epoll = {
    .base.type = OE_DEVID_EPOLL,
    .base.name = DEVICE_NAME,
    .base.ops.epoll = &_ops,
    .magic = EPOLL_MAGIC,
    .ready_mask = 0,
    .max_event_data = 0,
    .num_event_data = 0,
    .pevent_data = NULL,
};

oe_result_t oe_load_module_polling(void)
{
    oe_result_t result = OE_FAILURE;
    static bool _loaded = false;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

    if (!_loaded)
    {
        oe_spin_lock(&_lock);

        if (!_loaded)
        {
            const uint64_t devid = OE_DEVID_EPOLL;

            /* Allocate the device id. */
            if (oe_allocate_devid(devid) != devid)
            {
                OE_TRACE_ERROR("devid=%lu", devid);
                goto done;
            }

            /* Add to the device table. */
            if (oe_set_devid_device(devid, &_epoll.base) != 0)
            {
                OE_TRACE_ERROR("devid=%lu", devid);
                goto done;
            }
        }

        oe_spin_unlock(&_lock);
    }

    result = OE_OK;

done:
    return result;
}
