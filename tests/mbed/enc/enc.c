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
#include "../host/args.h"

int main(int argc, const char* argv[]);
int checkerflag = 0;
typedef struct _SyscallArgs
{
    char* path;
    int flags;
    int mode;
    int fd;
    void* ptr;
    int ret;
    int len;
} SyscallArgs;

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

char* oe_host_stack_strdup(const char* str)
{
    size_t n = oe_strlen(str);
    char* dup = (char*)oe_host_malloc(n + 1);

    if (dup)
        oe_memcpy(dup, str, n + 1);

    return dup;
}
void catenate(char* full_str, char* part_str, int len)
{
    strncat(full_str, part_str, len);
}
void test_checker(char* st)
{
    char str[300];
    strcpy(str, st);
    char* checker = "\n--------------------------------------------------------"
                    "--------------------\n\n";
    int i;
    int total_tests, skipped_tests;
    char* token[6];
    if (checkerflag == 1)
    {
        token[0] = strtok(str, " ");
        if (!(strcmp(token[0], "PASSED")))
        {
            for (i = 1; i < 6; i++)
            {
                token[i] = strtok(NULL, " ");
            }
            total_tests = atoi(token[3]);
            skipped_tests = atoi((token[5] + 1));

            if ((total_tests == 0) || (total_tests == skipped_tests))
            {
                abort();
            }
        }
    }
    if (strcmp(str, checker) == 0)
    {
        checkerflag = 1;
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
                SyscallArgs* args;
                args = (SyscallArgs*)oe_host_malloc(sizeof(SyscallArgs));
                args->path = oe_host_stack_strdup((const char*)arg1);
                args->flags = (int)arg2;
                args->mode = (int)arg3;
                oe_call_host("mbed_test_open", args);
                *ret = args->fd;
                oe_host_free(args->path);
                oe_host_free(args);
                OE_RAISE(OE_OK);
            }
            break;
        }
        case SYS_readv:
        {
            SyscallArgs* args;
            args = (SyscallArgs*)oe_host_malloc(sizeof(SyscallArgs));
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
            OE_RAISE(OE_OK);
            break;
        }
        case SYS_close:
        {
            SyscallArgs* args;
            args = (SyscallArgs*)oe_host_malloc(sizeof(SyscallArgs));
            args->fd = (int)arg1;
            oe_call_host("mbed_test_close", args);
            *ret = args->ret;
            oe_host_free(args);
            OE_RAISE(OE_OK);
            break;
        }
        case SYS_writev:
        {
            char str_full[1000] = {0};
            int i;
            const struct iovec* iov = (const struct iovec*)arg2;
            unsigned long iovcnt = (unsigned long)arg3;
            for (i = 0; i < iovcnt; i++)
            {
                catenate(str_full, iov[i].iov_base, iov[i].iov_len);
            }
            test_checker(str_full);
            break;
        }
    }

    OE_RAISE(OE_UNSUPPORTED);

done:
    return result;
}

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__);

        // Install a syscall hook to handle special behavior for mbed TLS.
        oe_register_syscall_hook(_syscall_hook);

        // verbose option is enabled as some of the functionality in
        // helper.function such as redirect output, restore output is trying
        // to assign values to stdout which in turn causes segmentation fault.
        // To avoid this we enabled verbose options such that those function
        // calls will be suppressed.
        if (0 == strcmp(
                     __TEST__,
                     "../../3rdparty/mbedtls/mbedtls/programs/test/selftest.c"))
        {
            // selftest treats the verbose flag "-v" as an invalid test suite
            // name,
            // so drop all args when invoking the test, which will execute all
            // selftests
            static const char* noargs[2] = {NULL};
            args->ret = main(1, noargs);
        }
        else
        {
            static const char* argv[] = {"test", "-v", "NULL"};
            static int argc = sizeof(argv) / sizeof(argv[0]);
            argv[2] = args->test;
            args->ret = main(argc, argv);
        }
        args->test = oe_host_strndup(__TEST__, OE_SIZE_MAX);
    }
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

void oe_handle_verify_report(uint64_t argIn, uint64_t* argOut)
{
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
