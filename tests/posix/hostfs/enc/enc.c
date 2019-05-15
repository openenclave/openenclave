// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>

void test_hostfs(const char* tmp_dir)
{
    extern int run_main(const char* tmp_dir);

    if (oe_load_module_console_file_system() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_console_file_system() failed\n");
        exit(1);
    }

    if (oe_load_module_host_file_system() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_posix() failed\n");
        exit(1);
    }

    if (mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    if (run_main(tmp_dir) != 0)
    {
        assert("_run_main() failed" == NULL);
        exit(1);
    }

    if (umount("/") != 0)
    {
        fprintf(stderr, "umount() failed\n");
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
