// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <openenclave/host.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../syscall_args.h"

OE_OCALL void mbed_test_open(void* syscall_args)
{
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    args->fd = open(args->path, args->flags, args->mode);

    return;
}

OE_OCALL void mbed_test_read(void* syscall_args)
{
    int ret;
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    ret = read(args->fd, (char*)args->ptr, args->len);
    args->ret = ret;

    return;
}

OE_OCALL void mbed_test_readv(void* syscall_args)
{
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    args->ret = readv(args->fd, (const struct iovec*)args->ptr, args->len);

    return;
}

OE_OCALL void mbed_test_close(void* syscall_args)
{
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    args->ret = close(args->fd);

    return;
}
