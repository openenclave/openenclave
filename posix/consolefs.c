// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "posix_t.h"

#define MAGIC 0x0b292bab

typedef struct _file
{
    oe_fd_t base;
    uint32_t magic;
    oe_host_fd_t host_fd;
} file_t;

static file_t* _cast_file(const oe_fd_t* desc)
{
    file_t* file = (file_t*)desc;

    if (file == NULL || file->magic != MAGIC)
        return NULL;

    return file;
}

static int _consolefs_dup(oe_fd_t* file_, oe_fd_t** new_file_out)
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
        *new_file_out = (oe_fd_t*)new_file;
    }

    ret = 0;

done:
    return ret;
}

static int _consolefs_release(oe_fd_t* desc)
{
    int ret = -1;

    if (!desc)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Free the desc without closing the file descriptor. */
    oe_free(desc);

done:
    return ret;
}

static int _consolefs_ioctl(oe_fd_t* desc, unsigned long request, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(desc);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_ioctl_ocall(&ret, file->host_fd, request, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static int _consolefs_fcntl(oe_fd_t* desc, int cmd, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(desc);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_fcntl_ocall(&ret, file->host_fd, cmd, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_read(oe_fd_t* file_, void* buf, size_t count)
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

static ssize_t _consolefs_write(oe_fd_t* file_, const void* buf, size_t count)
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

static oe_host_fd_t _consolefs_gethostfd(oe_fd_t* file_)
{
    oe_host_fd_t ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = file->host_fd;

done:
    return ret;
}

static oe_off_t _consolefs_lseek(oe_fd_t* file_, oe_off_t offset, int whence)
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

static int _consolefs_close(oe_fd_t* file_)
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

static oe_file_operations_t _ops = {
    .base.dup = _consolefs_dup,
    .base.release = _consolefs_release,
    .base.ioctl = _consolefs_ioctl,
    .base.fcntl = _consolefs_fcntl,
    .base.read = _consolefs_read,
    .base.write = _consolefs_write,
    .base.get_host_fd = _consolefs_gethostfd,
    .base.close = _consolefs_close,
    .lseek = _consolefs_lseek,
    .getdents = NULL,
};

static oe_fd_t* _new_file(oe_host_fd_t host_fd)
{
    oe_fd_t* ret = NULL;
    file_t* file = NULL;

    if (!(file = oe_calloc(1, sizeof(file_t))))
        goto done;

    file->base.type = OE_FD_TYPE_FILE;
    file->base.ops.file = _ops;
    file->magic = MAGIC;
    file->host_fd = host_fd;

    ret = &file->base;

done:
    return ret;
}

oe_fd_t* oe_consolefs_create_file(uint32_t fileno)
{
    switch (fileno)
    {
        case OE_STDIN_FILENO:
            return _new_file(OE_STDIN_FILENO);
        case OE_STDOUT_FILENO:
            return _new_file(OE_STDOUT_FILENO);
        case OE_STDERR_FILENO:
            return _new_file(OE_STDERR_FILENO);
        default:
            return NULL;
    }
}
