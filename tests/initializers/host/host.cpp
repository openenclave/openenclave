// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <cstdio>

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>

#include "../args.h"

static void _globals_test(oe_enclave_t* enclave)
{
    global_args args = {.global_int = 2,
                        .global_float = 2.0,
                        .global_ptr = (int*)0x2,
                        .global_struct = {2, 2},
                        .global_union = {.y = 2},
                        .global_array = {2, 2, 2, 2},
                        .get_default = 1};

    OE_TEST(oe_call_enclave(enclave, "get_globals", &args) == OE_OK);

    /* Verify default global initialization works in the enclave. */
    OE_TEST(args.global_int == 0);
    OE_TEST(args.global_float == 0.0);
    OE_TEST(args.global_ptr == NULL);
    OE_TEST(args.global_struct.a == 0 && args.global_struct.b == 0);
    OE_TEST(args.global_union.y == 0);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.global_array[i] == 0);

    /* Verify explicit global initialization works in the enclave. */
    args.get_default = 0;
    OE_TEST(oe_call_enclave(enclave, "get_globals", &args) == OE_OK);
    OE_TEST(args.global_int == 1);
    OE_TEST(args.global_float == 1.0);
    OE_TEST((uintptr_t)args.global_ptr == 0x1);
    OE_TEST(args.global_struct.a == 1 && args.global_struct.b == 1);
    OE_TEST(args.global_union.y == 1);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.global_array[i] == 1);

    /* Verify if we can set the globals. */
    global_args args2 = {.global_int = 2,
                         .global_float = 2.0,
                         .global_ptr = (int*)0x2,
                         .global_struct = {2, 2},
                         .global_union = {.y = 2},
                         .global_array = {2, 2, 2, 2},
                         .get_default = 0};

    OE_TEST(oe_call_enclave(enclave, "set_globals", &args2) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "get_globals", &args) == OE_OK);

    OE_TEST(args.global_int == 2);
    OE_TEST(args.global_float == 2.0);
    OE_TEST((uintptr_t)args.global_ptr == 0x2);
    OE_TEST(args.global_struct.a == 2 && args.global_struct.b == 2);
    OE_TEST(args.global_union.y == 2);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.global_array[i] == 2);
}

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

    result = oe_create_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    printf("===Starting globals test.\n");
    _globals_test(enclave);

    printf("===All tests pass.\n");

    oe_terminate_enclave(enclave);

    return 0;
}
