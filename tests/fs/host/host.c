// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "fs_u.h"
int rmdir(const char* path);

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH SRC_DIR BIN_DIR\n", argv[0]);
        return 1;
    }

    const char* enclave_path = argv[1];
    const char* src_dir = argv[2];
    const char* tmp_dir = argv[3];

    rmdir(tmp_dir);

    r = oe_create_fs_enclave(enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_fs(enclave, src_dir, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");

    return 0;
}
