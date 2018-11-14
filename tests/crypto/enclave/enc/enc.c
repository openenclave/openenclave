// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/syscall.h>
#include <openenclave/internal/tests.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../../tests.h"
#include "../syscall_args.h"

char* oe_host_strdup(const char* str)
{
    size_t n = oe_strlen(str);
    char* dup = (char*)oe_host_malloc(n + 1);

    if (dup)
        oe_memcpy(dup, str, n + 1);

    return dup;
}

static oe_result_t _syscall_hook(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6,
    long* ret)
{
    oe_result_t result = OE_UNEXPECTED;

    if (ret)
        *ret = -1;

    if (!ret)
        OE_RAISE(OE_INVALID_PARAMETER);

    switch (number)
    {
        case SYS_open:
        {
            const int flags = (const int)arg2;
            if (flags == O_RDONLY)
            {
                syscall_args_t* args;
                args = (syscall_args_t*)oe_host_malloc(sizeof(syscall_args_t));
                args->path = oe_host_strdup((const char*)arg1);
                args->flags = (int)arg2;
                args->mode = (int)arg3;
                oe_call_host("f_open", args);
                *ret = args->fd;
                oe_host_free(args->path);
                oe_host_free(args);
                result = OE_OK;
            }
            break;
        }
        case SYS_read:
        {
            syscall_args_t* args;
            args = (syscall_args_t*)oe_host_malloc(sizeof(syscall_args_t));
            char* enc_buf = (char*)arg2;
            char* host_buf = (void*)oe_host_malloc((size_t)arg3);
            args->ptr = (void*)host_buf;
            args->fd = (int)arg1;
            args->len = (int)arg3;
            oe_call_host("f_read", args);

            if ((args->ret) > 0)
                oe_memcpy(enc_buf, host_buf, (size_t)arg3);
            *ret = args->ret;
            oe_host_free(host_buf);

            oe_host_free(args);
            result = OE_OK;
            break;
        }
        case SYS_readv:
        {
            syscall_args_t* args;
            args = (syscall_args_t*)oe_host_malloc(sizeof(syscall_args_t));
            struct iovec* iov = (struct iovec*)arg2;
            int i;
            struct iovec* iov_host = (struct iovec*)oe_host_malloc(
                sizeof(struct iovec) * (size_t)arg3);
            for (i = 0; i < (int)arg3; i++)
            {
                iov_host[i].iov_base = (void*)oe_host_malloc(iov[i].iov_len);
                iov_host[i].iov_len = (size_t)iov[i].iov_len;
            }
            args->ptr = (void*)iov_host;
            args->fd = (int)arg1;
            args->len = (int)arg3;
            oe_call_host("f_readv", args);

            if ((args->ret) > 0)
                for (i = 0; i < (int)arg3; i++)
                    oe_memcpy(
                        iov[i].iov_base, iov_host[i].iov_base, iov[i].iov_len);
            *ret = args->ret;
            for (i = 0; i < (int)arg3; i++)
                oe_host_free(iov_host[i].iov_base);

            oe_host_free(iov_host);
            oe_host_free(args);
            result = OE_OK;
            break;
        }

        case SYS_close:
        {
            syscall_args_t* args;
            args = (syscall_args_t*)oe_host_malloc(sizeof(syscall_args_t));
            args->fd = (int)arg1;
            oe_call_host("f_close", args);
            *ret = args->ret;
            oe_host_free(args);
            result = OE_OK;
            break;
        }
        default:
        {
            OE_RAISE(OE_UNSUPPORTED);
        }
    }

done:
    return result;
}

void test()
{
    oe_register_syscall_hook(_syscall_hook);
    TestAll();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
