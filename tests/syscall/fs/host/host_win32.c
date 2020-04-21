// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <windows.h>

#include <openenclave/host.h>
#include <openenclave/internal/syscall/host.h>
#include <openenclave/internal/tests.h>
#include "fs_u.h"

#define SKIP_RETURN_CODE 2

int recursive_rmdir(wchar_t* path);

int wmain(int argc, wchar_t* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %ls ENCLAVE_PATH SRC_DIR BIN_DIR\n", argv[0]);
        return 1;
    }

    if ((flags & OE_ENCLAVE_FLAG_SIMULATE))
    {
        printf("=== Skipped unsupported test in simulation mode (sealKey)\n");
        return SKIP_RETURN_CODE;
    }

    /* create_enclave takes an ANSI path instead of a Unicode path, so we have
     * to try to convert here */
    char enclave_path[MAX_PATH];
    if (WideCharToMultiByte(
            CP_ACP,
            0,
            argv[1],
            -1,
            enclave_path,
            sizeof(enclave_path),
            NULL,
            NULL) == 0)
    {
        fprintf(stderr, "Invalid enclave path\n");
        return 1;
    }
    char* src_dir = oe_win_path_to_posix((PCWSTR)argv[2]);
    char* tmp_dir = oe_win_path_to_posix((PCWSTR)argv[3]);

    // Windows does not support umask.
    // Please set up the right permission to the parent directory.

    recursive_rmdir(argv[3]);

    r = oe_create_fs_enclave(enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_fs(enclave, src_dir, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");

    return 0;
}
