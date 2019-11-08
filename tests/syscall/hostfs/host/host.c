// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/syscall/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "test_hostfs_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TMP_DIR\n", argv[0]);
        return 1;
    }

    const char* enclave_path = argv[1];
    const char* tmp_dir = argv[2];

    r = oe_create_test_hostfs_enclave(
        enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

#if defined(_WIN32)
    tmp_dir = oe_win_path_to_posix(tmp_dir);
#endif
    r = test_hostfs(enclave, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (test_hostfs)\n");
#if defined(_WIN32)
    free(tmp_dir);
#endif

    return 0;
}
