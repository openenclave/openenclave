// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../syscall_args.h"
#include "crypto_u.h"

OE_OCALL void f_open(void* syscall_args)
{
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    args->fd = open(args->path, args->flags, args->mode);

    return;
}

OE_OCALL void f_read(void* syscall_args)
{
    int ret;
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    ret = read(args->fd, (char*)args->ptr, args->len);
    args->ret = ret;

    return;
}

OE_OCALL void f_readv(void* syscall_args)
{
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    args->ret = readv(args->fd, (const struct iovec*)args->ptr, args->len);

    return;
}

OE_OCALL void f_close(void* syscall_args)
{
    syscall_args_t* args = (syscall_args_t*)syscall_args;

    args->ret = close(args->fd);

    return;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_crypto_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if ((result = test(enclave)) != OE_OK)
        oe_put_err("test() failed: result=%u", result);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave() failed: %u\n", result);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
