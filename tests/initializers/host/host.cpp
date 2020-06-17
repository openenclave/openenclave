// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <cstdio>

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>

#include "initializers_u.h"

static void _globals_test(oe_enclave_t* enclave)
{
    int global_int = 2;
    float global_float = 2.0;
    int* global_ptr = (int*)0x2;
    dummy_struct global_struct = {2, 2};
    dummy_union global_union = {{0}};
    int global_array[4] = {2, 2, 2, 2};

    OE_TEST(
        get_globals(
            enclave,
            &global_int,
            &global_float,
            &global_ptr,
            &global_struct,
            &global_union,
            global_array,
            true) == OE_OK);

    /* Verify default global initialization works in the enclave. */
    OE_TEST(global_int == 0);
    OE_TEST(global_float == 0.0);
    OE_TEST(global_ptr == NULL);
    OE_TEST(global_struct.a == 0 && global_struct.b == 0);
    OE_TEST(global_union.y == 0);
    for (int i = 0; i < 4; i++)
        OE_TEST(global_array[i] == 0);

    /* Verify explicit global initialization works in the enclave. */
    OE_TEST(
        get_globals(
            enclave,
            &global_int,
            &global_float,
            &global_ptr,
            &global_struct,
            &global_union,
            global_array,
            false) == OE_OK);

    OE_TEST(global_int == 1);
    OE_TEST(global_float == 1.0);
    OE_TEST((uintptr_t)global_ptr == 0x1);
    OE_TEST(global_struct.a == 1 && global_struct.b == 1);
    OE_TEST(global_union.y == 1);
    for (int i = 0; i < 4; i++)
        OE_TEST(global_array[i] == 1);

    /* Verify if we can set the globals. */
    OE_TEST(
        set_globals(
            enclave,
            global_int,
            global_float,
            global_ptr,
            global_struct,
            global_union,
            global_array,
            true) == OE_OK);

    OE_TEST(
        get_globals(
            enclave,
            &global_int,
            &global_float,
            &global_ptr,
            &global_struct,
            &global_union,
            global_array,
            true) == OE_OK);

    OE_TEST(global_int == 1);
    OE_TEST(global_float == 1.0);
    OE_TEST((uintptr_t)global_ptr == 0x1);
    OE_TEST(global_struct.a == 1 && global_struct.b == 1);
    OE_TEST(global_union.y == 1);
    for (int i = 0; i < 4; i++)
        OE_TEST(global_array[i] == 1);
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

    result = oe_create_initializers_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    printf("===Starting globals test.\n");
    _globals_test(enclave);

    printf("===All tests pass.\n");

    oe_terminate_enclave(enclave);

    return 0;
}
