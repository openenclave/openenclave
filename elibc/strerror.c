// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/elibc/errno.h>
#include <openenclave/internal/enclavelibc.h>
#include <string.h>

struct pair
{
    int num;
    const char* str;
};

static struct pair _pairs[] = {
    {OE_EPERM, "Operation not permitted"},
    {OE_ENOENT, "No such file or directory"},
    {OE_ESRCH, "No such process"},
    {OE_EINTR, "Interrupted system call"},
    {OE_EIO, "Input/output error"},
    {OE_ENXIO, "No such device or address"},
    {OE_E2BIG, "Argument list too long"},
    {OE_ENOEXEC, "Exec format error"},
    {OE_EBADF, "Bad file descriptor"},
    {OE_ECHILD, "No child processes"},
    {OE_EAGAIN, "Resource temporarily unavailable"},
    {OE_ENOMEM, "Cannot allocate memory"},
    {OE_EACCES, "Permission denied"},
    {OE_EFAULT, "Bad address"},
    {OE_ENOTBLK, "Block device required"},
    {OE_EBUSY, "Device or resource busy"},
    {OE_EEXIST, "File exists"},
    {OE_EXDEV, "Invalid cross-device link"},
    {OE_ENODEV, "No such device"},
    {OE_ENOTDIR, "Not a directory"},
    {OE_EISDIR, "Is a directory"},
    {OE_EINVAL, "Invalid argument"},
    {OE_ENFILE, "Too many open files in system"},
    {OE_EMFILE, "Too many open files"},
    {OE_ENOTTY, "Inappropriate ioctl for device"},
    {OE_ETXTBSY, "Text file busy"},
    {OE_EFBIG, "File too large"},
    {OE_ENOSPC, "No space left on device"},
    {OE_ESPIPE, "Illegal seek"},
    {OE_EROFS, "Read-only file system"},
    {OE_EMLINK, "Too many links"},
    {OE_EPIPE, "Broken pipe"},
    {OE_EDOM, "Numerical argument out of domain"},
    {OE_ERANGE, "Numerical result out of range"},
    {OE_EDEADLK, "Resource deadlock avoided"},
    {OE_ENAMETOOLONG, "File name too long"},
    {OE_ENOLCK, "No locks available"},
    {OE_ENOSYS, "Function not implemented"},
    {OE_ENOTEMPTY, "Directory not empty"},
    {OE_ELOOP, "Too many levels of symbolic links"},
    {OE_EWOULDBLOCK, "Resource temporarily unavailable"},
    {OE_ENOMSG, "No message of desired type"},
    {OE_EIDRM, "Identifier removed"},
    {OE_ECHRNG, "Channel number out of range"},
    {OE_EL2NSYNC, "Level 2 not synchronized"},
    {OE_EL3HLT, "Level 3 halted"},
    {OE_EL3RST, "Level 3 reset"},
    {OE_ELNRNG, "Link number out of range"},
    {OE_EUNATCH, "Protocol driver not attached"},
    {OE_ENOCSI, "No CSI structure available"},
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

    return oe_strlcpy(buf, str, buflen) >= buflen ? OE_ERANGE : 0;
}
