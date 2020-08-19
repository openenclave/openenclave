// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/fd.h>
#include <openenclave/internal/syscall/fdtable.h>
#include <openenclave/internal/syscall/iov.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/sys/ioctl.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "syscall_t.h"

#define MAGIC 0x0b292bab

typedef struct _file
{
    oe_fd_t base;
    uint32_t magic;
    oe_host_fd_t host_fd;
} file_t;

static oe_file_ops_t _get_ops(void);

static file_t* _cast_file(const oe_fd_t* file_)
{
    file_t* file = (file_t*)file_;

    if (file == NULL || file->magic != MAGIC)
        return NULL;

    return file;
}

static int _consolefs_dup(oe_fd_t* file_, oe_fd_t** new_file_out)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    file_t* new_file = NULL;

    if (new_file_out)
        *new_file_out = NULL;

    if (!file || !new_file_out)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Allocate and initialize a new file structure. */
    {
        if (!(new_file = oe_calloc(1, sizeof(file_t))))
            OE_RAISE_ERRNO(OE_ENOMEM);

        new_file->base.type = OE_FD_TYPE_FILE;
        new_file->base.ops.file = _get_ops();
        new_file->magic = MAGIC;
    }

    /* Ask the host to perform this operation. */
    {
        oe_host_fd_t retval = -1;

        if (oe_syscall_dup_ocall(&retval, file->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval == -1)
            OE_RAISE_ERRNO(oe_errno);

        new_file->host_fd = retval;
    }

    *new_file_out = (oe_fd_t*)new_file;

    ret = 0;
    new_file = NULL;

done:

    if (new_file)
        oe_free(new_file);

    return ret;
}

static int _consolefs_ioctl(oe_fd_t* file_, unsigned long request, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /*
     * MUSL uses the TIOCGWINSZ ioctl request to determine whether the file
     * descriptor refers to a terminal device (such as stdin, stdout, and
     * stderr) so that it can use line-bufferred input and output. This check
     * fails when delegated to the host since this implementation opens the
     * devices by name (/dev/stdin, /dev/stderr, /dev/stdout). So the following
     * block works around this problem by implementing TIOCGWINSZ on the
     * enclave side. Other terminal control ioctls are left unimplemented.
     */
    if (request == OE_TIOCGWINSZ)
    {
        struct winsize
        {
            unsigned short int ws_row;
            unsigned short int ws_col;
            unsigned short int ws_xpixel;
            unsigned short int ws_ypixel;
        };
        struct winsize* p;

        if (!(p = (struct winsize*)arg))
            OE_RAISE_ERRNO(OE_EINVAL);

        p->ws_row = 24;
        p->ws_col = 80;
        p->ws_xpixel = 0;
        p->ws_ypixel = 0;

        ret = 0;
        goto done;
    }

    if (oe_syscall_ioctl_ocall(&ret, file->host_fd, request, arg, 0, NULL) !=
        OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static int _consolefs_fcntl(oe_fd_t* file_, int cmd, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    void* argout = NULL;
    uint64_t argsize = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    switch (cmd)
    {
        case OE_F_GETFD:
        case OE_F_SETFD:
        case OE_F_GETFL:
        case OE_F_SETFL:
            break;

        case OE_F_GETLK:
        case OE_F_OFD_GETLK:
            argsize = sizeof(struct oe_flock);
            argout = (void*)arg;
            break;

        case OE_F_SETLKW:
        case OE_F_SETLK:
        {
            void* srcp = (void*)arg;
            argsize = sizeof(struct oe_flock64);
            argout = (void*)arg;
            memcpy(argout, srcp, argsize);
            break;
        }

        case OE_F_OFD_SETLK:
        case OE_F_OFD_SETLKW:
        {
            void* srcp = (void*)arg;
            argsize = sizeof(struct oe_flock64);
            argout = (void*)arg;
            memcpy(argout, srcp, argsize);
            break;
        }

        // for sockets
        default:
        case OE_F_DUPFD:
        case OE_F_SETOWN:
        case OE_F_GETOWN:
        case OE_F_SETSIG:
        case OE_F_GETSIG:
        case OE_F_SETOWN_EX:
        case OE_F_GETOWN_EX:
        case OE_F_GETOWNER_UIDS:
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (oe_syscall_fcntl_ocall(
            &ret, file->host_fd, cmd, arg, argsize, argout) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_read(oe_fd_t* file_, void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_read_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_write(oe_fd_t* file_, const void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_write_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_readv(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!file || !iov || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    if (oe_syscall_readv_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /* Synchronize data read with IO vector. */
    if (oe_iov_sync(iov, iovcnt, buf, buf_size) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static ssize_t _consolefs_writev(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!file || (!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    if (oe_syscall_writev_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    if (buf)
        oe_free(buf);

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

    OE_UNUSED(file_);
    OE_UNUSED(offset);
    OE_UNUSED(whence);
    OE_RAISE_ERRNO(OE_ESPIPE);

done:
    return ret;
}

static ssize_t _consolefs_pread(
    oe_fd_t* file_,
    void* buf,
    size_t count,
    oe_off_t offset)
{
    ssize_t ret = -1;

    OE_UNUSED(file_);
    OE_UNUSED(buf);
    OE_UNUSED(count);
    OE_UNUSED(offset);
    OE_RAISE_ERRNO(OE_ESPIPE);

done:
    return ret;
}

static ssize_t _consolefs_pwrite(
    oe_fd_t* file_,
    const void* buf,
    size_t count,
    oe_off_t offset)
{
    ssize_t ret = -1;

    OE_UNUSED(file_);
    OE_UNUSED(buf);
    OE_UNUSED(count);
    OE_UNUSED(offset);
    OE_RAISE_ERRNO(OE_ESPIPE);

done:
    return ret;
}

static int _consolefs_close(oe_fd_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Ask the host to perform this operation. */
    {
        if (oe_syscall_close_ocall(&ret, file->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (ret == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Free the file structure. */
    oe_free(file);

done:
    return ret;
}

static int _consolefs_getdents64(
    oe_fd_t* file,
    struct oe_dirent* dirp,
    uint32_t count)
{
    OE_UNUSED(file);
    OE_UNUSED(dirp);
    OE_UNUSED(count);

    /* The standard devices are not directories, so this is unsupported. */
    OE_RAISE_ERRNO(OE_ENOTSUP);

done:
    return -1;
}

static int _consolefs_fstat(oe_fd_t* file, struct oe_stat_t* buf)
{
    OE_UNUSED(file);
    OE_UNUSED(buf);
    OE_RAISE_ERRNO(OE_ENOTSUP);
done:
    return -1;
}

static int _consolefs_fsync(oe_fd_t* file)
{
    OE_UNUSED(file);
    OE_RAISE_ERRNO(OE_EINVAL);
done:
    return -1;
}

static oe_file_ops_t _ops = {
    .fd.read = _consolefs_read,
    .fd.write = _consolefs_write,
    .fd.readv = _consolefs_readv,
    .fd.writev = _consolefs_writev,
    .fd.dup = _consolefs_dup,
    .fd.ioctl = _consolefs_ioctl,
    .fd.fcntl = _consolefs_fcntl,
    .fd.close = _consolefs_close,
    .fd.get_host_fd = _consolefs_gethostfd,
    .lseek = _consolefs_lseek,
    .pread = _consolefs_pread,
    .pwrite = _consolefs_pwrite,
    .getdents64 = _consolefs_getdents64,
    .fstat = _consolefs_fstat,
    .fsync = _consolefs_fsync,
    .fdatasync = _consolefs_fsync,
};

static oe_file_ops_t _get_ops(void)
{
    return _ops;
}

static oe_fd_t* _new_file(uint32_t fileno)
{
    oe_fd_t* ret = NULL;
    file_t* file = NULL;

    if (fileno > OE_STDERR_FILENO)
        goto done;

    /* Create the file struct. */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
            goto done;

        file->base.type = OE_FD_TYPE_FILE;
        file->base.ops.file = _ops;
        file->magic = MAGIC;
    }

    /* Ask the host to duplicate the file descriptor. */
    {
        oe_host_fd_t retval;

        if (oe_syscall_dup_ocall(&retval, fileno) != OE_OK)
            goto done;

        if (retval < 0)
            goto done;

        file->host_fd = retval;
    }

    ret = &file->base;
    file = NULL;

done:

    if (file)
        oe_free(file);

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
