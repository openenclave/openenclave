// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include <fcntl.h>
#include <openenclave/host.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

typedef struct _SyscallArgs
{
    char* path;
    int flags;
    int mode;
    int fd;
    void* ptr;
    int ret;
    int len;
} Args;

OE_OCALL void mbed_test_open(void* syscallArgs)
{
    int fd;
    Args* args = (Args*)syscallArgs;

    OE_TRACE_INFO("#### %s ###########\n", args->path);
    fd = open(args->path, args->flags, args->mode);
    if (fd < 0)
        printf("fopen error");
    else
    {
        OE_TRACE_INFO("\n file opened address fd =%d &&&&&&&&&\n", fd);
        args->fd = fd;
    }

    return;
}

OE_OCALL void mbed_test_readv(void* syscallArgs)
{
    int ret;
    Args* args = (Args*)syscallArgs;

    ret = readv(args->fd, (const struct iovec*)args->ptr, args->len);
    if (ret < 0)
        printf("readv error");
    else
        args->ret = ret;

    return;
}

OE_OCALL void mbed_test_close(void* syscallArgs)
{
    int ret;
    Args* args = (Args*)syscallArgs;

    ret = close(args->fd);
    if (ret < 0)
        printf("close error");
    else
        args->ret = ret;

    return;
}
