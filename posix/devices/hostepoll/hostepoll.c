// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <openenclave/enclave.h>

#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/iov.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "posix_t.h"

/* The map allocation grows in multiples of the chunk size. */
#define MAP_CHUNK_SIZE 1024

#define DEVICE_MAGIC 0x4504f4c
#define EPOLL_MAGIC 0x708f5a51

/* epoll_ctl(OE_EPOLL_CTL_ADD) establishes this pair. */
typedef struct _pair
{
    /* The fd parameter from epoll_ctl(). */
    int fd;

    /* The event parameter from epoll_ctl(). */
    struct oe_epoll_event event;
} pair_t;

typedef struct _device
{
    struct _oe_device base;
    uint32_t magic;
} device_t;

typedef struct _epoll
{
    oe_fd_t base;
    uint32_t magic;
    oe_host_fd_t host_fd;

    /* Mappings added by epoll_ctl(OE_EPOLL_CTL_ADD) */
    pair_t* map;
    size_t map_size;
    size_t map_capacity;
    oe_spinlock_t lock;
} epoll_t;

static oe_epoll_ops_t _get_epoll_ops(void);

static device_t* _cast_device(const oe_device_t* device_)
{
    device_t* device = (device_t*)device_;

    if (device == NULL || device->magic != DEVICE_MAGIC)
        return NULL;

    return device;
}

static epoll_t* _cast_epoll(const oe_fd_t* epoll_)
{
    epoll_t* epoll = (epoll_t*)epoll_;

    if (epoll == NULL || epoll->magic != EPOLL_MAGIC)
        return NULL;

    return epoll;
}

static int _map_reserve(epoll_t* epoll, size_t new_capacity)
{
    int ret = -1;

    new_capacity = oe_round_up_to_multiple(new_capacity, MAP_CHUNK_SIZE);

    if (new_capacity > epoll->map_capacity)
    {
        pair_t* p;
        size_t n = new_capacity;

        /* Reallocate the table. */
        if (!(p = oe_realloc(epoll->map, n * sizeof(pair_t))))
            goto done;

        /* Zero-fill the unused portion. */
        {
            const size_t num_bytes = (n - epoll->map_size) * sizeof(pair_t);
            void* ptr = p + epoll->map_size;

            if (oe_memset_s(ptr, num_bytes, 0, num_bytes) != OE_OK)
                goto done;
        }

        epoll->map = p;
        epoll->map_capacity = new_capacity;
    }

    ret = 0;

done:
    return ret;
}

static pair_t* _map_find(epoll_t* epoll, int fd)
{
    for (size_t i = 0; i < epoll->map_size; i++)
    {
        pair_t* pair = &epoll->map[i];

        if (pair->fd == fd)
            return pair;
    }

    /* Not found */
    return NULL;
}

static oe_fd_t* _epoll_create1(oe_device_t* device_, int32_t flags)
{
    oe_fd_t* ret = NULL;
    epoll_t* epoll = NULL;
    device_t* device = _cast_device(device_);
    oe_host_fd_t retval;

    oe_errno = 0;

    if (!device)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(epoll = oe_calloc(1, sizeof(epoll_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    if (oe_posix_epoll_create1_ocall(&retval, flags) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (retval != -1)
    {
        epoll->base.type = OE_FD_TYPE_EPOLL;
        epoll->base.ops.epoll = _get_epoll_ops();
        epoll->magic = EPOLL_MAGIC;
        epoll->host_fd = retval;
    }

    ret = &epoll->base;
    epoll = NULL;

done:

    if (epoll)
        oe_free(epoll);

    return ret;
}

static oe_fd_t* _epoll_create(oe_device_t* device_, int size)
{
    /* The size argument is ignored according to the manpage. */
    OE_UNUSED(size);

    /* Delegate with flags=0. */
    return _epoll_create1(device_, 0);
}

static int _epoll_ctl_add(epoll_t* epoll, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_fd_t* desc;
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    struct oe_epoll_event host_event;
    int retval;
    bool locked = false;

    oe_errno = 0;

    /* Check parameters. */
    if (!epoll || !event)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    /* Get the host fd for the epoll object. */
    host_epfd = epoll->host_fd;

    /* Get the host fd for the fd. */
    if ((host_fd = desc->ops.fd.get_host_fd(desc)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    /* Initialize the host event. */
    {
        const size_t num_bytes = sizeof(host_event);

        if (oe_memset_s(&host_event, num_bytes, 0, num_bytes) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        host_event.events = event->events;
        host_event.data.fd = fd;
    }

    if (oe_posix_epoll_ctl_ocall(
            &retval, host_epfd, OE_EPOLL_CTL_ADD, host_fd, &host_event) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (retval != -1)
    {
        oe_spin_lock(&epoll->lock);
        locked = true;

        if (_map_reserve(epoll, epoll->map_size + 1) != 0)
            OE_RAISE_ERRNO(OE_ENOMEM);

        epoll->map[epoll->map_size].fd = fd;
        epoll->map[epoll->map_size].event = *event;
        epoll->map_size++;
    }

    ret = retval;

done:

    if (locked)
        oe_spin_unlock(&epoll->lock);

    return ret;
}

static int _epoll_ctl_mod(epoll_t* epoll, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_fd_t* desc;
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    struct oe_epoll_event host_event;
    int retval;

    oe_errno = 0;

    /* Check parameters. */
    if (!epoll || !event)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    /* Get the host fd for the epoll device. */
    host_epfd = epoll->host_fd;

    /* Get the host fd for the device. */
    if ((host_fd = desc->ops.fd.get_host_fd(desc)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    /* Initialize the host event. */
    {
        const size_t num_bytes = sizeof(host_event);

        if (oe_memset_s(&host_event, num_bytes, 0, num_bytes) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        host_event.events = event->events;
        host_event.data.fd = fd;
    }

    if (oe_posix_epoll_ctl_ocall(
            &retval, host_epfd, OE_EPOLL_CTL_MOD, host_fd, &host_event) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(oe_errno);
    }

    /* Modify the pair. */
    if (retval == 0)
    {
        pair_t* pair;

        oe_spin_lock(&epoll->lock);
        {
            if ((pair = _map_find(epoll, fd)))
                pair->event = *event;
        }
        oe_spin_unlock(&epoll->lock);

        if (!pair)
            OE_RAISE_ERRNO(OE_ENOENT);
    }

    ret = 0;

done:
    return ret;
}

static int _epoll_ctl_del(epoll_t* epoll, int fd)
{
    int ret = -1;
    oe_fd_t* desc;
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    int retval;

    oe_errno = 0;

    /* Check parameters. */
    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    /* Get the host fd for the epoll device. */
    host_epfd = epoll->host_fd;

    /* Get the host fd for the device. */
    if ((host_fd = desc->ops.fd.get_host_fd(desc)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_posix_epoll_ctl_ocall(
            &retval, host_epfd, OE_EPOLL_CTL_DEL, host_fd, NULL) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /* Delete the pair. */
    if (retval == 0)
    {
        bool found = false;

        oe_spin_lock(&epoll->lock);
        {
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
        }
        oe_spin_unlock(&epoll->lock);

        if (!found)
            OE_RAISE_ERRNO(OE_ENOENT);
    }

    ret = 0;

done:
    return ret;
}

static int _epoll_ctl(
    oe_fd_t* epoll_,
    int op,
    int fd,
    struct oe_epoll_event* event)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    switch (op)
    {
        case OE_EPOLL_CTL_ADD:
        {
            ret = _epoll_ctl_add(epoll, fd, event);
            goto done;
        }

        case OE_EPOLL_CTL_MOD:
        {
            ret = _epoll_ctl_mod(epoll, fd, event);
            goto done;
        }

        case OE_EPOLL_CTL_DEL:
        {
            ret = _epoll_ctl_del(epoll, fd);
            goto done;
        }

        default:
        {
            OE_RAISE_ERRNO(OE_EINVAL);
            return -1;
        }
    }

    ret = 0;

done:
    return ret;
}

static int _epoll_wait(
    oe_fd_t* epoll_,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout)
{
    int ret = -1;
    int retval;
    epoll_t* epoll = _cast_epoll(epoll_);
    oe_host_fd_t host_epfd = -1;

    if (!epoll || !events || maxevents <= 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_errno = 0;

    if ((host_epfd = epoll_->ops.fd.get_host_fd(epoll_)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_posix_epoll_wait_ocall(
            &retval, host_epfd, events, (unsigned int)maxevents, timeout) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (retval > 0)
    {
        if (retval > maxevents)
            OE_RAISE_ERRNO(OE_EINVAL);

        for (int i = 0; i < retval; i++)
        {
            struct oe_epoll_event* event = &events[i];
            const pair_t* pair;

            oe_spin_lock(&epoll->lock);
            {
                if ((pair = _map_find(epoll, event->data.fd)))
                    event->data.u64 = pair->event.data.u64;
            }
            oe_spin_unlock(&epoll->lock);

            if (!pair)
                OE_RAISE_ERRNO(OE_ENOENT);
        }
    }

    ret = (int)retval;

done:

    return ret;
}

static int _epoll_close(oe_fd_t* epoll_)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);
    int retval = -1;

    oe_errno = 0;

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Close the file descriptor on the host side. */
    if (oe_posix_epoll_close_ocall(&retval, epoll->host_fd) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (retval == -1)
        OE_RAISE_ERRNO(oe_errno);

    if (epoll->map)
        oe_free(epoll->map);

    oe_free(epoll);

    ret = 0;

done:
    return ret;
}

static int _epoll_release(oe_device_t* epoll_)
{
    int ret = -1;
    device_t* epoll = _cast_device(epoll_);

    oe_errno = 0;

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Release the epoll_ object. */
    oe_free(epoll);

    ret = 0;

done:
    return ret;
}

static oe_host_fd_t _epoll_get_host_fd(oe_fd_t* epoll_)
{
    epoll_t* epoll = _cast_epoll(epoll_);
    return epoll->host_fd;
}

static int _epoll_ioctl(oe_fd_t* epoll_, unsigned long request, uint64_t arg)
{
    int ret = -1;
    epoll_t* file = _cast_epoll(epoll_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_ioctl_ocall(&ret, file->host_fd, request, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static int _epoll_fcntl(oe_fd_t* epoll_, int cmd, uint64_t arg)
{
    int ret = -1;
    epoll_t* file = _cast_epoll(epoll_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_fcntl_ocall(&ret, file->host_fd, cmd, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _epoll_read(oe_fd_t* epoll_, void* buf, size_t count)
{
    ssize_t ret = -1;
    epoll_t* file = _cast_epoll(epoll_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_posix_read_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _epoll_write(oe_fd_t* epoll_, const void* buf, size_t count)
{
    ssize_t ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);

    oe_errno = 0;

    /* Check parameters. */
    if (!epoll || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_posix_write_ocall(&ret, epoll->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _epoll_readv(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    void* buf = NULL;
    size_t buf_size;

    if (!iov || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Calculate the size of the read buffer. */
    if ((buf_size = oe_iov_compute_size(iov, (size_t)iovcnt)) == (size_t)-1)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Allocate the read buffer. */
    if (!(buf = oe_malloc(buf_size)))
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Perform the read. */
    if ((ret = _epoll_read(desc, buf, buf_size)) <= 0)
        goto done;

    if (oe_iov_inflate(
            buf, (size_t)ret, (struct oe_iovec*)iov, (size_t)iovcnt) != 0)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static ssize_t _epoll_writev(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    void* buf = NULL;
    size_t buf_size = 0;

    if (!iov || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Create the write buffer from the IOV vector. */
    if (oe_iov_deflate(iov, (size_t)iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    ret = _epoll_write(desc, buf, buf_size);

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static int _epoll_dup(oe_fd_t* epoll_, oe_fd_t** new_epoll_out)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);
    epoll_t* new_epoll = NULL;
    oe_host_fd_t retval;

    oe_errno = 0;

    if (new_epoll_out)
        *new_epoll_out = NULL;

    /* Check parameters. */
    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call host: */
    {
        if (oe_posix_dup_ocall(&retval, epoll->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Create the new epoll object. */
    {
        if (!(new_epoll = oe_calloc(1, sizeof(epoll_t))))
            OE_RAISE_ERRNO(oe_errno);

        new_epoll->base.type = OE_FD_TYPE_EPOLL;
        new_epoll->base.ops.epoll = _get_epoll_ops();
        new_epoll->magic = EPOLL_MAGIC;
        new_epoll->host_fd = retval;

        if (epoll->map && epoll->map_size)
        {
            pair_t* map;

            if (!(map = oe_calloc(epoll->map_size, sizeof(pair_t))))
                OE_RAISE_ERRNO(OE_ENOMEM);

            memcpy(map, epoll->map, epoll->map_size * sizeof(pair_t));
            new_epoll->map = map;
            new_epoll->map_size = epoll->map_size;
        }

        *new_epoll_out = &new_epoll->base;
        new_epoll = NULL;
    }

    ret = 0;

done:

    if (new_epoll)
        oe_free(new_epoll);

    return ret;
}

static oe_epoll_ops_t _epoll_ops = {
    .fd.read = _epoll_read,
    .fd.write = _epoll_write,
    .fd.readv = _epoll_readv,
    .fd.writev = _epoll_writev,
    .fd.dup = _epoll_dup,
    .fd.ioctl = _epoll_ioctl,
    .fd.fcntl = _epoll_fcntl,
    .fd.close = _epoll_close,
    .fd.get_host_fd = _epoll_get_host_fd,
    .epoll_ctl = _epoll_ctl,
    .epoll_wait = _epoll_wait,
};

static oe_epoll_ops_t _get_epoll_ops(void)
{
    return _epoll_ops;
}

// clang-format off
static device_t _device =
{
    .base.type = OE_DEVICE_TYPE_EPOLL,
    .base.name = OE_DEVICE_NAME_HOST_EPOLL,
    .base.ops.epoll =
    {
        .base.release = _epoll_release,
        .epoll_create = _epoll_create,
        .epoll_create1 = _epoll_create1,
    },
    .magic = DEVICE_MAGIC,
};
// clang-format on

oe_result_t oe_load_module_host_epoll(void)
{
    oe_result_t result = OE_UNEXPECTED;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    static bool _loaded = false;

    oe_spin_lock(&_lock);

    if (!_loaded)
    {
        if (oe_device_table_set(OE_DEVID_HOST_EPOLL, &_device.base) != 0)
        {
            /* Do not propagate errno to caller. */
            oe_errno = 0;
            OE_RAISE(OE_FAILURE);
        }

        _loaded = true;
    }

    result = OE_OK;

done:
    oe_spin_unlock(&_lock);

    return result;
}
