// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <pthread.h>
#include <stdio.h>
#include <sys/mount.h>
#include "oegencert_t.h"

static bool _initialized;
static pthread_once_t _once = PTHREAD_ONCE_INIT;

static void _init(void)
{
    if (oe_load_module_host_file_system() != OE_OK)
        return;

    _initialized = true;
}

int oegencert_ecall(void)
{
    int ret = -1;
    bool mounted = false;
    extern int oegencert(void);

    if (pthread_once(&_once, _init) != 0 || !_initialized)
    {
        fprintf(stderr, "initialization failed\n");
        goto done;
    }

    /* Mount the host file system */
    {
        if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
        {
            fprintf(stderr, "failed to mount the host file system\n");
            goto done;
        }

        mounted = true;
    }

    if (oegencert() != 0)
    {
        fprintf(stderr, "oegencert() failed\n");
        goto done;
    }

    ret = 0;

done:

    if (mounted)
        umount("/");

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
