// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/globals.h>
#include "oeio_t.h"

oe_pid_t oe_getpid(void)
{
    oe_pid_t ret = 0;
    oe_posix_getpid(&ret);
    return ret;
}

oe_pid_t oe_getppid(void)
{
    oe_pid_t ret = 0;
    oe_posix_getppid(&ret);
    return ret;
}

oe_pid_t oe_getpgrp(void)
{
    oe_pid_t ret = 0;
    oe_posix_getpgrp(&ret);
    return ret;
}

oe_uid_t oe_getuid(void)
{
    oe_uid_t ret = 0;
    oe_posix_getuid(&ret);
    return ret;
}

oe_uid_t oe_geteuid(void)
{
    oe_uid_t ret = 0;
    oe_posix_geteuid(&ret);
    return ret;
}

oe_gid_t oe_getgid(void)
{
    oe_gid_t ret = 0;
    oe_posix_getgid(&ret);
    return ret;
}

oe_gid_t oe_getegid(void)
{
    oe_gid_t ret = 0;
    oe_posix_getegid(&ret);
    return ret;
}

oe_pid_t oe_getpgid(oe_pid_t pid)
{
    oe_pid_t ret = -1;
    oe_pid_t retval = -1;
    int err = 0;

    if (oe_posix_getpgid(&retval, pid, &err) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (retval == -1)
    {
        oe_errno = err;
        goto done;
    }

    ret = retval;

done:
    return ret;
}

int oe_getgroups(int size, oe_gid_t list[])
{
    int ret = -1;
    int retval = -1;
    int err;

    if (oe_posix_getgroups(&retval, (size_t)size, list, &err) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (retval == -1)
    {
        oe_errno = err;
        goto done;
    }

    ret = retval;

done:
    return ret;
}
