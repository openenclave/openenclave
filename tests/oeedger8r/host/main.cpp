// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <wchar.h>
#include "all_u.h"

void test_basic_edl_ecalls(oe_enclave_t* enclave);
void test_string_edl_ecalls(oe_enclave_t* enclave);
void test_wstring_edl_ecalls(oe_enclave_t* enclave);
void test_array_edl_ecalls(oe_enclave_t* enclave);
void test_pointer_edl_ecalls(oe_enclave_t* enclave);
void test_struct_edl_ecalls(oe_enclave_t* enclave);
void test_enum_edl_ecalls(oe_enclave_t* enclave);
void test_foreign_edl_ecalls(oe_enclave_t* enclave);
void run_misc_tests(oe_enclave_t* enclave);

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

    result = oe_create_all_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %u\n", argv[0], result);
        return 1;
    }

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

    test_foreign_edl_ecalls(enclave);
    OE_TEST(test_foreign_edl_ocalls(enclave) == OE_OK);

    run_misc_tests(enclave);

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (file)\n");

    return 0;
}
