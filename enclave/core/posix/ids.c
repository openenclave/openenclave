// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/globals.h>
#include "ids.h"
#include "oe_t.h"

pid_t oe_getpid(void)
{
    pid_t ret = 0;
    oe_posix_getpid(&ret);
    return ret;
}

pid_t oe_getppid(void)
{
    pid_t ret = 0;
    oe_posix_getppid(&ret);
    return ret;
}

pid_t oe_getpgrp(void)
{
    pid_t ret = 0;
    oe_posix_getpgrp(&ret);
    return ret;
}

uid_t oe_getuid(void)
{
    uid_t ret = 0;
    oe_posix_getuid(&ret);
    return ret;
}

uid_t oe_geteuid(void)
{
    uid_t ret = 0;
    oe_posix_geteuid(&ret);
    return ret;
}

gid_t oe_getgid(void)
{
    gid_t ret = 0;
    oe_posix_getgid(&ret);
    return ret;
}

gid_t oe_getegid(void)
{
    gid_t ret = 0;
    oe_posix_getegid(&ret);
    return ret;
}

pid_t oe_getpgid(pid_t pid)
{
    pid_t ret = -1;
    pid_t retval = -1;
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

int oe_getgroups(int size, gid_t list[])
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
