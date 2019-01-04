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
#include "mbed_t.h"

int main(int argc, const char* argv[]);
struct mbed_args gmbed_args;

void _exit(int status)
{
    ocall_exit(status);
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
                int rval = 0;
                result =
                    mbed_test_open(&rval, (char*)arg1, (int)arg2, (mode_t)arg3);
                *ret = rval;
            }
            break;
        }
        case SYS_read:
        {
            ssize_t rval = 0;
            const size_t buf_len = (size_t)arg3;
            char* host_buf = (char*)oe_host_malloc(buf_len);
            result = mbed_test_read(&rval, (int)arg1, host_buf, buf_len);
            if (rval > 0)
            {
                char* enc_buf = (char*)arg2;
                oe_memcpy(enc_buf, host_buf, buf_len);
            }
            *ret = (int)rval;
            oe_host_free(host_buf);
            break;
        }
        case SYS_readv:
        {
            int i;
            struct iovec* iov = (struct iovec*)arg2;
            const int iovcnt = (int)arg3;
            struct iovec* host_iov = (struct iovec*)oe_host_malloc(
                sizeof(struct iovec) * (unsigned long)iovcnt);

            for (i = 0; i < iovcnt; ++i)
            {
                host_iov[i].iov_base = (void*)oe_host_malloc(iov[i].iov_len);
                host_iov[i].iov_len = iov[i].iov_len;
            }

            ssize_t rval = 0;
            result = mbed_test_readv(&rval, (int)arg1, host_iov, iovcnt);
            *ret = rval;

            for (i = 0; i < iovcnt; ++i)
            {
                if (rval > 0)
                {
                    oe_memcpy(
                        iov[i].iov_base, host_iov[i].iov_base, iov[i].iov_len);
                }
                oe_host_free(host_iov[i].iov_base);
            }
            oe_host_free(host_iov);
            break;
        }
        case SYS_writev:
        {
            char* str_full;
            size_t total_buff_len = 0;
            const struct iovec* iov = (const struct iovec*)arg2;
            int iovcnt = (int)arg3;
            // Calculating  buffer length
            for (int i = 0; i < iovcnt; i++)
            {
                total_buff_len += iov[i].iov_len;
            }
            // Considering string terminating character
            total_buff_len += 1;
            str_full = (char*)calloc(total_buff_len, sizeof(char));
            for (int i = 0; i < iovcnt; i++)
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
            int rval = 0;
            result = mbed_test_close(&rval, (int)arg1);
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

int test(
    const char* in_testname,
    char out_testname[STRLEN],
    struct mbed_args* args)
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
    strncpy(out_testname, __TEST__, STRLEN);
    out_testname[STRLEN - 1] = '\0';

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
