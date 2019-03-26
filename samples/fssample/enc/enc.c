// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include "sample_t.h"

static jmp_buf _jmp_buf;
static int _exit_status = OE_INT_MAX;

void oe_set_exit_handler(void (*handler)(int status));

static void _exit_handler(int status)
{
    _exit_status = status;
    longjmp(_jmp_buf, 1);
}

static int _run_main(int argc, const char* argv[])
{
    int ret;
    int main(int argc, const char* argv[]);

    if (setjmp(_jmp_buf) == 1)
    {
        return _exit_status;
    }

    oe_set_exit_handler(_exit_handler);

    if (mount("/", "/", "hostfs", 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    ret = main(argc, argv);

    return ret;
}

void test_sample(const char* tmp_dir)
{
    const int argc = 2;
    const char* argv[3];

    argv[0] = "./main";
    argv[1] = tmp_dir;
    argv[2] = NULL;

    if (_run_main(argc, argv) != 0)
    {
        assert("_run_main() failed" == NULL);
        exit(1);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
