// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(_WIN32)
#include <windows.h>
#endif
#include <openenclave/host.h>
#include <openenclave/internal/syscall/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "test_hostfs_u.h"

void test_hostfs_posix(const char* enclave_path, const char* tmp_dir)
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    r = oe_create_test_hostfs_enclave(
        enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_hostfs(enclave, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (test_hostfs)\n");
}

#if defined(_WIN32)
int recursive_rmdir(const wchar_t* path);

int wmain(int argc, const wchar_t* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %ls ENCLAVE_PATH TMP_DIR\n", argv[0]);
        return 1;
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
    char* win_path = oe_win_path_to_posix(argv[2]);

    recursive_rmdir(argv[2]);

    test_hostfs_posix(enclave_path, win_path);

    free(win_path);

    return 0;
}

#else /* !_WIN32 */
int recursive_rmdir(const char* path);

int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TMP_DIR\n", argv[0]);
        return 1;
    }

    recursive_rmdir(argv[2]);

    test_hostfs_posix(argv[1], argv[2]);

    return 0;
}
#endif
