// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/syscall.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../syscall_args.h"
#include "mbed_t.h"

int main(int argc, const char* argv[]);
struct mbed_args gmbed_args;

void _exit(int status)
{
    oe_call_host("ocall_exit", (void*)(long)status);
    abort();
}

void _Exit(int status)
{
    _exit(status);
    abort();
}

void exit(int status)
{
    _exit(status);
    abort();
}

char* oe_host_strdup(const char* str)
{
    size_t n = oe_strlen(str);
    char* dup = (char*)oe_host_malloc(n + 1);

    if (dup)
        oe_memcpy(dup, str, n + 1);

    return dup;
}
void test_checker(char* str)
{
    int i;
    char* token[6];
    if ((strncmp(str, "PASSED (", 8) == 0) && (strlen(str) >= 32))
    {
        token[0] = strtok(str, " ");
        for (i = 1; i < 6; i++)
        {
            token[i] = strtok(NULL, " ");
        }
        gmbed_args.total = atoi(token[3]);
        // Since the first character of subtoken is '('  avoiding it
        gmbed_args.skipped = atoi((token[5] + 1));
    }
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
    OE_UNUSED(arg4);
    OE_UNUSED(arg5);
    OE_UNUSED(arg6);

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
                oe_call_host("mbed_test_open", args);
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
            char* host_buf = (void*)oe_host_malloc(arg3);
            args->ptr = (void*)host_buf;
            args->fd = (int)arg1;
            args->len = (int)arg3;
            oe_call_host("mbed_test_read", args);

            if ((args->ret) > 0)
                oe_memcpy(enc_buf, host_buf, arg3);
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
            struct iovec* iov_host =
                (struct iovec*)oe_host_malloc(sizeof(struct iovec) * (int)arg3);
            for (i = 0; i < (int)arg3; i++)
            {
                iov_host[i].iov_base = (void*)oe_host_malloc(iov[i].iov_len);
                iov_host[i].iov_len = (size_t)iov[i].iov_len;
            }
            args->ptr = (void*)iov_host;
            args->fd = (int)arg1;
            args->len = (int)arg3;
            oe_call_host("mbed_test_readv", args);

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
        case SYS_writev:
        {
            char* str_full;
            int total_buff_len = 0;
            const struct iovec* iov = (const struct iovec*)arg2;
            unsigned long iovcnt = (unsigned long)arg3;
            // Calculating  buffer length
            for (size_t i = 0; i < iovcnt; i++)
            {
                total_buff_len = total_buff_len + iov[i].iov_len;
            }
            // Considering string terminating character
            total_buff_len += 1;
            str_full = (char*)calloc(total_buff_len, sizeof(char));
            for (size_t i = 0; i < iovcnt; i++)
            {
                strncat(str_full, iov[i].iov_base, iov[i].iov_len);
            }
            test_checker(str_full);
            free(str_full);
            // expecting the runtime implementation of SYS_writev to also be
            // called.
            result = OE_UNSUPPORTED;
            break;
        }
        case SYS_close:
        {
            syscall_args_t* args;
            args = (syscall_args_t*)oe_host_malloc(sizeof(syscall_args_t));
            args->fd = (int)arg1;
            oe_call_host("mbed_test_close", args);
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

int test(const char* in_testname, char** out_testname, struct mbed_args* args)
{
    int return_value = -1;
    printf("RUNNING: %s\n", __TEST__);

    // Install a syscall hook to handle special behavior for mbed TLS.
    oe_register_syscall_hook(_syscall_hook);

    // verbose option is enabled as some of the functionality in helper.function
    // such as redirect output, restore output is trying to assign values to
    // stdout which in turn causes segmentation fault.  To avoid this we enabled
    // verbose options such that those function calls will be suppressed.
    if (0 == strcmp(
                 __TEST__,
                 "../../3rdparty/mbedtls/mbedtls/programs/test/selftest.c"))
    {
        // selftest treats the verbose flag "-v" as an invalid test suite name,
        // so drop all args when invoking the test, which will execute all
        // selftests
        static const char* noargs[2] = {NULL};
        return_value = main(1, noargs);
    }
    else
    {
        static const char* argv[] = {"test", "-v", "NULL"};
        static int argc = sizeof(argv) / sizeof(argv[0]);
        argv[2] = in_testname;
        return_value = main(argc, argv);
        args->skipped = gmbed_args.skipped;
        args->total = gmbed_args.total;
    }
    *out_testname = oe_host_strndup(__TEST__, OE_SIZE_MAX);

    return return_value;
}

/*
 **==============================================================================
 **
 ** oe_handle_verify_report():
 **
 **     Since liboeenclave is not linked, we must define a version of this
 **     function here (since liboecore depends on it). This version asserts
 **     and aborts().
 **
 **==============================================================================
 */

void oe_handle_verify_report(uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(arg_in);
    OE_UNUSED(arg_out);
    assert("oe_handle_verify_report()" == NULL);
    abort();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
