// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/syscall/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "fs_u.h"

#define SKIP_RETURN_CODE 2

int recursive_rmdir(const char* path);

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

    if ((flags & OE_ENCLAVE_FLAG_SIMULATE))
    {
        printf("=== Skipped unsupported test in simulation mode (sealKey)\n");
        return SKIP_RETURN_CODE;
    }

    const char* enclave_path = argv[1];
    char* src_dir = (char*)argv[2];
    char* tmp_dir = (char*)argv[3];

    umask(0022);

    recursive_rmdir(tmp_dir);

    r = oe_create_fs_enclave(enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_fs(enclave, src_dir, tmp_dir);
    OE_TEST(r == OE_OK);

    recursive_rmdir(tmp_dir);

    r = test_fs_linux(enclave, src_dir, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");

    return 0;
}
