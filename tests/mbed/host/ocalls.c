// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
    int fd;
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    fd = open(args->path, args->flags, args->mode);
    args->fd = fd;

    return;
}

OE_OCALL void mbed_test_readv(void* syscall_args)
{
    int ret;
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    ret = readv(args->fd, (const struct iovec*)args->ptr, args->len);
    args->ret = ret;

    return;
}

OE_OCALL void mbed_test_close(void* syscall_args)
{
    int ret;
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    ret = close(args->fd);
    args->ret = ret;

    return;
}

OE_OCALL void mbed_test_check_results(void* test_results)
{
    int ret;
    test_result_t* args = (test_result_t*)test_results;

    if(args->total == 0)
	assert ( "args->total" == NULL);
    else if (args->total == args->skipped)
	assert ("args->total" == "args->skipped");
    return;
}
