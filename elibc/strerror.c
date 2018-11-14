// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/internal/enclavelibc.h>
#include <string.h>

struct pair
{
    int num;
    const char* str;
};

static struct pair _pairs[] = {
    {ELIBC_EPERM, "Operation not permitted"},
    {ELIBC_ENOENT, "No such file or directory"},
    {ELIBC_ESRCH, "No such process"},
    {ELIBC_EINTR, "Interrupted system call"},
    {ELIBC_EIO, "Input/output error"},
    {ELIBC_ENXIO, "No such device or address"},
    {ELIBC_E2BIG, "Argument list too long"},
    {ELIBC_ENOEXEC, "Exec format error"},
    {ELIBC_EBADF, "Bad file descriptor"},
    {ELIBC_ECHILD, "No child processes"},
    {ELIBC_EAGAIN, "Resource temporarily unavailable"},
    {ELIBC_ENOMEM, "Cannot allocate memory"},
    {ELIBC_EACCES, "Permission denied"},
    {ELIBC_EFAULT, "Bad address"},
    {ELIBC_ENOTBLK, "Block device required"},
    {ELIBC_EBUSY, "Device or resource busy"},
    {ELIBC_EEXIST, "File exists"},
    {ELIBC_EXDEV, "Invalid cross-device link"},
    {ELIBC_ENODEV, "No such device"},
    {ELIBC_ENOTDIR, "Not a directory"},
    {ELIBC_EISDIR, "Is a directory"},
    {ELIBC_EINVAL, "Invalid argument"},
    {ELIBC_ENFILE, "Too many open files in system"},
    {ELIBC_EMFILE, "Too many open files"},
    {ELIBC_ENOTTY, "Inappropriate ioctl for device"},
    {ELIBC_ETXTBSY, "Text file busy"},
    {ELIBC_EFBIG, "File too large"},
    {ELIBC_ENOSPC, "No space left on device"},
    {ELIBC_ESPIPE, "Illegal seek"},
    {ELIBC_EROFS, "Read-only file system"},
    {ELIBC_EMLINK, "Too many links"},
    {ELIBC_EPIPE, "Broken pipe"},
    {ELIBC_EDOM, "Numerical argument out of domain"},
    {ELIBC_ERANGE, "Numerical result out of range"},
    {ELIBC_EDEADLK, "Resource deadlock avoided"},
    {ELIBC_ENAMETOOLONG, "File name too long"},
    {ELIBC_ENOLCK, "No locks available"},
    {ELIBC_ENOSYS, "Function not implemented"},
    {ELIBC_ENOTEMPTY, "Directory not empty"},
    {ELIBC_ELOOP, "Too many levels of symbolic links"},
    {ELIBC_EWOULDBLOCK, "Resource temporarily unavailable"},
    {ELIBC_ENOMSG, "No message of desired type"},
    {ELIBC_EIDRM, "Identifier removed"},
    {ELIBC_ECHRNG, "Channel number out of range"},
    {ELIBC_EL2NSYNC, "Level 2 not synchronized"},
    {ELIBC_EL3HLT, "Level 3 halted"},
    {ELIBC_EL3RST, "Level 3 reset"},
    {ELIBC_ELNRNG, "Link number out of range"},
    {ELIBC_EUNATCH, "Protocol driver not attached"},
    {ELIBC_ENOCSI, "No CSI structure available"},
};

static const int _npairs = sizeof(_pairs) / sizeof(_pairs[0]);

static const char _unknown[] = "Unknown error";

char* elibc_strerror(int errnum)
{
    for (size_t i = 0; i < _npairs; i++)
    {
        if (_pairs[i].num == errnum)
            return (char*)_pairs[i].str;
    }

    return (char*)_unknown;
}

int elibc_strerror_r(int errnum, char* buf, size_t buflen)
{
    const char* str = NULL;

    for (size_t i = 0; i < _npairs; i++)
    {
        if (_pairs[i].num == errnum)
        {
            str = _pairs[i].str;
            break;
        }
    }

    if (!str)
        str = _unknown;

    return strlcpy(buf, str, buflen) >= buflen ? ELIBC_ERANGE : 0;
}
