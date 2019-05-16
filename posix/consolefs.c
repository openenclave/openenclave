// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "posix_t.h"

#define MAGIC 0x0b292bab

typedef struct _file
{
    struct _oe_device base;
    uint32_t magic;
    oe_host_fd_t host_fd;
} file_t;

static file_t* _cast_file(const oe_device_t* device)
{
    file_t* file = (file_t*)device;

    if (file == NULL || file->magic != MAGIC)
        return NULL;

    return file;
}

static int _consolefs_dup(oe_device_t* file_, oe_device_t** new_file_out)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    oe_host_fd_t retval = -1;

    if (new_file_out)
        *new_file_out = NULL;

    if (!file || !new_file_out)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Ask the host to perform this operation. */
    {
        oe_errno = 0;

        if (oe_posix_dup_ocall(&retval, file->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Allocate and initialize a new file structure. */
    {
        file_t* new_file;

        if (!(new_file = oe_calloc(1, sizeof(file_t))))
            OE_RAISE_ERRNO(OE_ENOMEM);

        *new_file = *file;
        new_file->host_fd = retval;
        *new_file_out = (oe_device_t*)new_file;
    }

    ret = 0;

done:
    return ret;
}

static int _consolefs_release(oe_device_t* dev)
{
    int ret = -1;

    if (!dev)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Free the device without closing the file descriptor. */
    oe_free(dev);

done:
    return ret;
}

static int _consolefs_ioctl(
    oe_device_t* dev,
    unsigned long request,
    uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(dev);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_ioctl_ocall(&ret, file->host_fd, request, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static int _consolefs_fcntl(oe_device_t* dev, int cmd, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(dev);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_fcntl_ocall(&ret, file->host_fd, cmd, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_read(oe_device_t* file_, void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_read_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_write(
    oe_device_t* file_,
    const void* buf,
    size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_write_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static oe_host_fd_t _consolefs_gethostfd(oe_device_t* file_)
{
    oe_host_fd_t ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = file->host_fd;

done:
    return ret;
}

static oe_off_t _consolefs_lseek(
    oe_device_t* file_,
    oe_off_t offset,
    int whence)
{
    oe_off_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_lseek_ocall(&ret, file->host_fd, offset, whence) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static int _consolefs_close(oe_device_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Ask the host to perform this operation. */
    {
        if (oe_posix_close_ocall(&ret, file->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (ret == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Free the file structure. */
    oe_free(file);

done:
    return ret;
}

static oe_fs_ops_t _ops = {
    .base.dup = _consolefs_dup,
    .base.release = _consolefs_release,
    .base.ioctl = _consolefs_ioctl,
    .base.fcntl = _consolefs_fcntl,
    .open = NULL,
    .base.read = _consolefs_read,
    .base.write = _consolefs_write,
    .base.get_host_fd = _consolefs_gethostfd,
    .clone = NULL,
    .mount = NULL,
    .unmount = NULL,
    .lseek = _consolefs_lseek,
    .base.close = _consolefs_close,
    .getdents = NULL,
    .stat = NULL,
    .access = NULL,
    .link = NULL,
    .unlink = NULL,
    .rename = NULL,
    .truncate = NULL,
    .mkdir = NULL,
    .rmdir = NULL,
};

static file_t* _new_file(oe_host_fd_t host_fd)
{
    file_t* ret = NULL;
    file_t* file = NULL;

    if (!(file = oe_calloc(1, sizeof(file_t))))
        goto done;

    file->base.type = OE_DEVICE_TYPE_FILESYSTEM;
    file->base.name = OE_DEVICE_NAME_CONSOLE_FILE_SYSTEM;
    file->base.ops.fs = &_ops;
    file->magic = MAGIC;
    file->host_fd = host_fd;

    ret = file;

done:
    return ret;
}

static oe_once_t _once = OE_ONCE_INITIALIZER;
static bool _loaded;

static void _load_once(void)
{
    int ret = -1;
    static file_t* stdin_file = NULL;
    static file_t* stdout_file = NULL;
    static file_t* stderr_file = NULL;

    /* Create STDIN device */
    {
        if (!(stdin_file = _new_file(OE_DEVICE_TYPE_FILESYSTEM)))
            goto done;

        if (oe_fdtable_reassign(OE_STDIN_FILENO, &stdin_file->base) != 0)
            OE_RAISE_ERRNO(oe_errno);

        stdin_file = NULL;
    }

    /* Create STDOUT device */
    {
        if (!(stdout_file = _new_file(OE_DEVICE_TYPE_FILESYSTEM)))
            goto done;

        if (oe_fdtable_reassign(OE_STDOUT_FILENO, &stdout_file->base) != 0)
            OE_RAISE_ERRNO(oe_errno);

        stdout_file = NULL;
    }

    /* Create STDERR device */
    {
        if (!(stderr_file = _new_file(OE_DEVICE_TYPE_FILESYSTEM)))
            goto done;

        if (oe_fdtable_reassign(OE_STDERR_FILENO, &stderr_file->base) != 0)
            OE_RAISE_ERRNO(oe_errno);

        stderr_file = NULL;
    }

    ret = 0;

done:

    if (stdin_file)
        oe_free(stdin_file);

    if (stdout_file)
        oe_free(stdout_file);

    if (stderr_file)
        oe_free(stderr_file);

    if (ret == 0)
        _loaded = true;
}

oe_result_t oe_load_module_console_file_system(void)
{
    if (oe_once(&_once, _load_once) != OE_OK || !_loaded)
        return OE_FAILURE;

    return OE_OK;
}
