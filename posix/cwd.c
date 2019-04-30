// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/internal/trace.h>

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
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (!buf)
    {
        n = OE_PATH_MAX;
        p = oe_malloc(n);

        if (!p)
        {
            oe_errno = ENOMEM;
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
        oe_errno = ERANGE;
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
        oe_errno = ENOTDIR;
        return -1;
    }

    /* Set the _cwd global. */
    oe_pthread_spin_lock(&_lock);
    locked = true;

    if (oe_strlcpy(_cwd, real_path, OE_PATH_MAX) >= OE_PATH_MAX)
    {
        oe_errno = ENAMETOOLONG;
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
