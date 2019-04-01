// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/sgxfs.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>

void test_sgxfs(const char* tmp_dir)
{
    extern int run_main(const char* tmp_dir);

    if (oe_register_sgxfs() != OE_OK)
    {
        fprintf(stderr, "oe_register_sgxfs() failed\n");
        exit(1);
    }

    if (mount("/", "/", "sgxfs", 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    if (run_main(tmp_dir) != 0)
    {
        assert("run_main() failed" == NULL);
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
