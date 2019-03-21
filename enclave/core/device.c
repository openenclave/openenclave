// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>

static const size_t ELEMENT_SIZE = sizeof(oe_device_t*);
static const size_t CHUNK_SIZE = 8;
static oe_array_t _dev_arr = OE_ARRAY_INITIALIZER(ELEMENT_SIZE, CHUNK_SIZE);
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static bool _initialized = false;

static oe_once_t _device_id_once = OE_ONCE_INIT;
static oe_thread_key_t _device_id_key = OE_THREADKEY_INITIALIZER;

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

uint64_t oe_allocate_devid(uint64_t devid)
{
    uint64_t ret = OE_DEVID_NULL;
    bool locked = false;

    if (!_initialized && _init_table() != 0)
    {
        oe_errno = ENOMEM;
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= _dev_arr.size)
    {
        if (oe_array_resize(&_dev_arr, devid + 1) != 0)
        {
            oe_errno = ENOMEM;
            goto done;
        }
    }

    if (_table()[devid] != NULL)
    {
        oe_errno = EADDRINUSE;
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
        oe_errno = ENOMEM;
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= _dev_arr.size)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (_table()[devid] == NULL)
    {
        oe_errno = EINVAL;
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
        oe_errno = EINVAL;
        goto done;
    }

    if (_table()[devid] != NULL)
    {
        oe_errno = EADDRINUSE;
        goto done;
    }

    _table()[devid] = device;

    ret = 0;

done:
    return ret;
}

oe_device_t* oe_get_devid_device(uint64_t devid)
{
    oe_device_t* ret = NULL;

    if (devid >= _table_size())
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = _table()[devid];

done:
    return ret;
}

int oe_remove_device(uint64_t devid)
{
    int ret = -1;
    oe_device_t* device;

    if (!(device = oe_get_devid_device(devid)))
        goto done;

    if (device->ops.base->shutdown == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if ((*device->ops.base->shutdown)(device) != 0)
    {
        goto done;
    }

    ret = 0;

done:
    return ret;
}

ssize_t oe_read(int fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    oe_device_t* device;
    ssize_t n;

    if (!(device = oe_get_fd_device(fd)))
        goto done;

    if (device->ops.base->read == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    // The action routine sets errno
    if ((n = (*device->ops.base->read)(device, buf, count)) < 0)
        goto done;

    ret = n;

done:
    return ret;
}

ssize_t oe_write(int fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    oe_device_t* device;

    if (!(device = oe_get_fd_device(fd)))
    {
        oe_errno = EBADF;
        goto done;
    }

    if (device->ops.base->write == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    // The action routine sets errno
    ret = (*device->ops.base->write)(device, buf, count);

done:
    return ret;
}

int oe_close(int fd)
{
    int ret = -1;
    oe_device_t* device = oe_get_fd_device(fd);

    if (!device)
    {
        goto done;
    }

    if (device->ops.base->close == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    if ((*device->ops.base->close)(device) != 0)
    {
        goto done;
    }

    oe_release_fd(fd);

    ret = 0;

done:
    return ret;
}

int oe_ioctl_va(int fd, unsigned long request, oe_va_list ap)
{
    int ret = -1;

    switch (fd)
    {
        case OE_STDIN_FILENO:
        case OE_STDERR_FILENO:
        case OE_STDOUT_FILENO:
        {
            static const unsigned long _TIOCGWINSZ = 0x5413;

            if (request == _TIOCGWINSZ)
            {
                struct winsize
                {
                    unsigned short int ws_row;
                    unsigned short int ws_col;
                    unsigned short int ws_xpixel;
                    unsigned short int ws_ypixel;
                };
                struct winsize* p;

                p = oe_va_arg(ap, struct winsize*);

                if (!p)
                    goto done;

                p->ws_row = 24;
                p->ws_col = 80;
                p->ws_xpixel = 0;
                p->ws_ypixel = 0;

                ret = 0;
                goto done;
            }

            ret = -1;
            goto done;
        }
        default:
        {
            oe_device_t* pdevice = oe_get_fd_device(fd);

            if (!pdevice)
            {
                // Log error here
                return -1; // erno is already set
            }

            if (pdevice->ops.base->ioctl == NULL)
            {
                oe_errno = EINVAL;
                return -1;
            }

            // The action routine sets errno
            ret = (*pdevice->ops.base->ioctl)(pdevice, request, ap);
            goto done;
        }
    }

done:
    return ret;
}

int oe_ioctl(int fd, unsigned long request, ...)
{
    oe_va_list ap;
    oe_va_start(ap, request);
    int r = oe_ioctl_va(fd, request, ap);
    oe_va_end(ap);
    return r;
}

static void _create_device_id_key()
{
    if (oe_thread_key_create(&_device_id_key, NULL) != 0)
        oe_abort();
}

int oe_set_thread_device(uint64_t devid)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
        goto done;

    if (oe_once(&_device_id_once, _create_device_id_key) != 0)
        goto done;

    if (oe_thread_setspecific(_device_id_key, (void*)devid) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}

int oe_clear_thread_device(void)
{
    int ret = -1;

    if (oe_once(&_device_id_once, _create_device_id_key) != 0)
        goto done;

    if (oe_thread_setspecific(_device_id_key, NULL) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}

uint64_t oe_get_thread_device(void)
{
    uint64_t ret = OE_DEVID_NULL;
    uint64_t devid;

    if (oe_once(&_device_id_once, _create_device_id_key) != 0)
        goto done;

    if (!(devid = (uint64_t)oe_thread_getspecific(_device_id_key)))
        goto done;

    ret = devid;

done:
    return ret;
}
