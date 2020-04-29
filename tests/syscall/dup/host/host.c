// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(_WIN32)
#include <windows.h>
#endif
#include <openenclave/host.h>
#include <openenclave/internal/syscall/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "test_dup_u.h"

void test_dup_posix(const char* enclave_path, const char* posix_path)
{
    const uint32_t flags = oe_get_create_flags();

    oe_enclave_t* enclave = NULL;
    oe_result_t r = oe_create_test_dup_enclave(
        enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_dup(enclave, posix_path);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (test_dup)\n");
}

#if defined(_WIN32)
/* argv strings are in UTF-16LE */
int wmain(int argc, wchar_t* argv[])
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
    char* posix_path = oe_win_path_to_posix(argv[2]);

    test_dup_posix(enclave_path, posix_path);

    free(posix_path);

    return 0;
}

#else /* !_WIN32 */

/* argv strings are in UTF-8 */
int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TMP_DIR\n", argv[0]);
        return 1;
    }

    test_dup_posix(argv[1], argv[2]);

    return 0;
}
#endif
