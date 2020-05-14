// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/enclave.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>

void test_hostfs(const char* tmp_dir)
{
    extern int run_main(const char* tmp_dir);

    if (oe_load_module_host_file_system() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_file_system() failed\n");
        exit(1);
    }

    /* Mount with a relative source should fail */
    if (mount(".", "/", OE_HOST_FILE_SYSTEM, 0, NULL) == 0)
    {
        fprintf(stderr, "mount() with relative path should not succeed\n");
        exit(1);
    }
    else if (oe_errno != OE_EINVAL)
    {
        fprintf(
            stderr, "mount() with relative path should fail with OE_EINVAL\n");
        exit(1);
    }

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
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
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
