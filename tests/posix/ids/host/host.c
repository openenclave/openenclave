// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <unistd.h>
#include "test_ids_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const char* enclave_path = argv[1];

    r = oe_create_test_ids_enclave(
        enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    /* Ask enclvae to run the test. */
    {
        gid_t list[OE_NGROUPS_MAX] = {0};
        int required_size;
        int size;

        required_size = getgroups(0, NULL);
        OE_TEST(required_size >= 0);

        size = getgroups(required_size, list);
        OE_TEST(required_size == size);

        r = test_ids(
            enclave,
            getpid(),
            getppid(),
            getuid(),
            geteuid(),
            getgid(),
            getegid(),
            getpgrp(),
            list,
            (size_t)size);

        // size_t num_groups,
        //[in, count=num_groups] const gid_t* groups);

        OE_TEST(r == OE_OK);
    }

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (test_ids)\n");

    return 0;
}
