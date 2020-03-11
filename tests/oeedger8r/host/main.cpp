// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <wchar.h>
#include <algorithm>
#include <string>
#include "all_u.h"
#include "other_u.h" // Test that multiple enclaves can be shared with one host.

// The types wchar_t, long, unsigned long and long double have different sizes
// in Linux and Windows. Therefore enclaves built in Linux cannot be safely
// loaded if they use any of these types.
uint8_t g_enabled[4] = {true, true, true, true};

void test_basic_edl_ecalls(oe_enclave_t* enclave);
void test_string_edl_ecalls(oe_enclave_t* enclave);
void test_wstring_edl_ecalls(oe_enclave_t* enclave);
void test_array_edl_ecalls(oe_enclave_t* enclave);
void test_pointer_edl_ecalls(oe_enclave_t* enclave);
void test_struct_edl_ecalls(oe_enclave_t* enclave);
void test_enum_edl_ecalls(oe_enclave_t* enclave);
void test_foreign_edl_ecalls(oe_enclave_t* enclave);
void test_other_edl_ecalls(oe_enclave_t* enclave);
void test_deepcopy_edl_ecalls(oe_enclave_t* enclave);

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    std::string other("edl_other_enc");
    std::string other_lvi_cfg("edl_other_enc-lvi-cfg");
    // If we loaded `edl_other_enc` instead of `edl_enc`...
    if (std::equal(
            other.rbegin(), other.rend(), std::string(argv[1]).rbegin()) ||
        std::equal(
            other_lvi_cfg.rbegin(),
            other_lvi_cfg.rend(),
            std::string(argv[1]).rbegin()))
    {
        result = oe_create_other_enclave(
            argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
        if (result != OE_OK)
        {
            fprintf(stderr, "%s: cannot create enclave: %u\n", argv[0], result);
            return 1;
        }

        test_other_edl_ecalls(enclave);
        OE_TEST(test_other_edl_ocalls(enclave) == OE_OK);
        goto done;
    }

    result = oe_create_all_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %u\n", argv[0], result);
        return 1;
    }

    OE_TEST(configure(enclave, g_enabled) == OE_OK);

    // TODO: Sort these alphabetically.
    test_basic_edl_ecalls(enclave);
    OE_TEST(test_basic_edl_ocalls(enclave) == OE_OK);

    test_string_edl_ecalls(enclave);
    OE_TEST(test_string_edl_ocalls(enclave) == OE_OK);

    test_wstring_edl_ecalls(enclave);
    OE_TEST(test_wstring_edl_ocalls(enclave) == OE_OK);

    test_array_edl_ecalls(enclave);
    OE_TEST(test_array_edl_ocalls(enclave) == OE_OK);

    test_pointer_edl_ecalls(enclave);
    OE_TEST(test_pointer_edl_ocalls(enclave) == OE_OK);

    test_struct_edl_ecalls(enclave);
    OE_TEST(test_struct_edl_ocalls(enclave) == OE_OK);

    test_enum_edl_ecalls(enclave);
    OE_TEST(test_enum_edl_ocalls(enclave) == OE_OK);

    // Change the value of errno on the host side before making the ecall.
    // Ecalls do not transfer errno values from host to enclave.
    errno = 0xbadf00d;
    OE_TEST(test_errno_edl_ocalls(enclave) == OE_OK);

    test_foreign_edl_ecalls(enclave);
    OE_TEST(test_foreign_edl_ocalls(enclave) == OE_OK);

    test_deepcopy_edl_ecalls(enclave);

    OE_TEST(test_switchless_edl_ocalls(enclave) == OE_OK);
done:
    oe_terminate_enclave(enclave);

    printf("=== passed all tests (file)\n");

    return 0;
}
