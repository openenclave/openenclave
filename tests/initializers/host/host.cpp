// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <cstdio>

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>

#include "../args.h"

static void _GlobalsTest(oe_enclave_t* enclave)
{
    GlobalArgs args = {.globalInt = 2,
                       .globalFloat = 2.0,
                       .globalPtr = (int*)0x2,
                       .globalStruct = {2, 2},
                       .globalUnion = {.y = 2},
                       .globalArray = {2, 2, 2, 2},
                       .getDefault = 1};

    OE_TEST(oe_call_enclave(enclave, "GetGlobals", &args) == OE_OK);

    /* Verify default global initialization works in the enclave. */
    OE_TEST(args.globalInt == 0);
    OE_TEST(args.globalFloat == 0.0);
    OE_TEST(args.globalPtr == NULL);
    OE_TEST(args.globalStruct.a == 0 && args.globalStruct.b == 0);
    OE_TEST(args.globalUnion.y == 0);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.globalArray[i] == 0);

    /* Verify explicit global initialization works in the enclave. */
    args.getDefault = 0;
    OE_TEST(oe_call_enclave(enclave, "GetGlobals", &args) == OE_OK);
    OE_TEST(args.globalInt == 1);
    OE_TEST(args.globalFloat == 1.0);
    OE_TEST((uintptr_t)args.globalPtr == 0x1);
    OE_TEST(args.globalStruct.a == 1 && args.globalStruct.b == 1);
    OE_TEST(args.globalUnion.y == 1);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.globalArray[i] == 1);

    /* Verify if we can set the globals. */
    GlobalArgs args2 = {.globalInt = 2,
                        .globalFloat = 2.0,
                        .globalPtr = (int*)0x2,
                        .globalStruct = {2, 2},
                        .globalUnion = {.y = 2},
                        .globalArray = {2, 2, 2, 2},
                        .getDefault = 0};

    OE_TEST(oe_call_enclave(enclave, "SetGlobals", &args2) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "GetGlobals", &args) == OE_OK);

    OE_TEST(args.globalInt == 2);
    OE_TEST(args.globalFloat == 2.0);
    OE_TEST((uintptr_t)args.globalPtr == 0x2);
    OE_TEST(args.globalStruct.a == 2 && args.globalStruct.b == 2);
    OE_TEST(args.globalUnion.y == 2);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.globalArray[i] == 2);
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
    _GlobalsTest(enclave);

    printf("===All tests pass.\n");

    oe_terminate_enclave(enclave);

    return 0;
}
