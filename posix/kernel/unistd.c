// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/time.h>
#include <openenclave/internal/trace.h>
#include "posix_t.h"

int oe_gethostname(char* name, size_t len)
{
    int ret = -1;
    struct oe_utsname uts;

    if ((ret = oe_uname(&uts)) != 0)
    {
        OE_TRACE_ERROR("name=%s len=%ld ret=%d", name, len, ret);
        ret = -1;
        goto done;
    }

    oe_strlcpy(name, uts.nodename, len);
    ret = 0;

done:
    return ret;
}

int oe_getdomainname(char* name, size_t len)
{
    int ret = -1;
    struct oe_utsname uts;

    if ((ret = oe_uname(&uts)) != 0)
    {
        OE_TRACE_ERROR("name=%s len=%ld ret=%d", name, len, ret);
        ret = -1;
        goto done;
    }

#ifdef _GNU_SOURCE
    oe_strlcpy(name, uts.domainname, len);
#else
    oe_strlcpy(name, uts.__domainname, len);
#endif
    ret = 0;

done:
    return ret;
}

static char _cwd[OE_PATH_MAX] = "/";
static oe_pthread_spinlock_t _lock;

char* oe_getcwd(char* buf, size_t size)
{
    char* ret = NULL;
    char* p = NULL;
    size_t n;
    bool locked = false;

    if (buf && size == 0)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (!buf)
    {
        n = OE_PATH_MAX;
        p = oe_malloc(n);

        if (!p)
        {
            oe_errno = OE_ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }
    }
    else
    {
        n = size;
        p = buf;
    }

    oe_pthread_spin_lock(&_lock);
    locked = true;

    if (oe_strlcpy(p, _cwd, n) >= n)
    {
        oe_errno = OE_ERANGE;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_pthread_spin_unlock(&_lock);
    locked = false;

    ret = p;
    p = NULL;

done:

    if (locked)
        oe_pthread_spin_unlock(&_lock);

    if (p && p != buf)
        oe_free(p);

    return ret;
}

int oe_chdir(const char* path)
{
    int ret = -1;
    char real_path[OE_PATH_MAX];
    struct oe_stat st;
    bool locked = false;

    /* Resolve to an absolute canonical path. */
    if (!oe_realpath(path, real_path))
        return -1;

    /* Fail if unable to stat the path. */
    if (oe_stat(real_path, &st) != 0)
    {
        // oe_errno set by oe_stat().
        return -1;
    }

    /* Fail if path not a directory. */
    if (!OE_S_ISDIR(st.st_mode))
    {
        oe_errno = OE_ENOTDIR;
        return -1;
    }

    /* Set the _cwd global. */
    oe_pthread_spin_lock(&_lock);
    locked = true;

    if (oe_strlcpy(_cwd, real_path, OE_PATH_MAX) >= OE_PATH_MAX)
    {
        oe_errno = OE_ENAMETOOLONG;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_pthread_spin_unlock(&_lock);
    locked = false;

    ret = 0;

done:

    if (locked)
        oe_pthread_spin_unlock(&_lock);

    return ret;
}

unsigned int oe_sleep(unsigned int seconds)
{
    const uint64_t ONE_SECOND = 1000;
    const uint64_t msec = seconds * ONE_SECOND;

    return (oe_sleep_msec(msec) == 0) ? 0 : seconds;
}

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

    if (oe_posix_getpgid(&retval, pid) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (retval == -1)
        goto done;

    ret = retval;

done:
    return ret;
}

int oe_getgroups(int size, oe_gid_t list[])
{
    int ret = -1;
    int retval = -1;

    if (oe_posix_getgroups(&retval, (size_t)size, list) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (retval == -1)
    {
        goto done;
    }

    ret = retval;

done:
    return ret;
}
