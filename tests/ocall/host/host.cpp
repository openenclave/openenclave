// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

static bool _func1Called = false;

OE_OCALL void Func1(void* args)
{
    _func1Called = true;
}

OE_OCALL void my_ocall(void* arg)
{
    my_ocall_args_t* args = (my_ocall_args_t*)arg;

    if (args)
        args->out = args->in * 7;
}

static bool _func2Ok = false;

OE_OCALL void Func2(void* args)
{
    // unsigned char* buf = (unsigned char*)args;
    _func2Ok = true;
}

static bool _funcACalled = false;

OE_OCALL void A(void* args)
{
    _funcACalled = true;
}

static oe_enclave_t* _enclave = NULL;
static bool _reentrancyTested = false;

OE_OCALL void TestReentrancy(void*)
{
    oe_result_t result;

    // misspelt functions are caught by the host.
    result = oe_call_enclave(_enclave, "foobar", NULL);
    OE_TEST(result == OE_NOT_FOUND);

    // Valid function; but reentrant call.
    result = oe_call_enclave(_enclave, "TestReentrancy", NULL);
    printf("result ==== %s\n", oe_result_str(result));
    OE_TEST(result == OE_INVALID_REENTRANT_ECALL);

    _reentrancyTested = true;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    /* Call Test2() */
    {
        Test2Args args;
        args.in = 123456789;
        args.out = 0;
        oe_result_t result = oe_call_enclave(enclave, "Test2", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.out == args.in);
    }

    /* Call Test4() */
    {
        oe_result_t result = oe_call_enclave(enclave, "Test4", NULL);
        OE_TEST(result == OE_OK);
        OE_TEST(_func2Ok);
    }

    /* Call was_destructor_called() */
    {
        oe_result_t result;

        was_destructor_called_args_t args;
        args.called = true;
        result = oe_call_enclave(enclave, "was_destructor_called", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.called == false);
    }

    /* Call SetTSD() */
    {
        SetTSDArgs args;
        args.value = strdup("TSD-DATA");
        oe_result_t result = oe_call_enclave(enclave, "SetTSD", &args);
        OE_TEST(result == OE_OK);
    }

    /* Call was_destructor_called() */
    {
        oe_result_t result;

        was_destructor_called_args_t args;
        args.called = false;
        result = oe_call_enclave(enclave, "was_destructor_called", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.called == true);
    }

    /* Call GetTSD() */
    {
        GetTSDArgs args;
        args.value = 0;
        oe_result_t result = oe_call_enclave(enclave, "GetTSD", &args);
        OE_TEST(result == OE_OK);
        /* Returning from SetTSD() cleared this TSD slot */
        OE_TEST(args.value == NULL);
    }

    /* Call TestMyOCall() */
    {
        TestMyOCallArgs args;
        args.result = 0;
        result = oe_call_enclave(enclave, "TestMyOCall", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.result == 7000);
    }

    /* Call TestOCallEdgeCases() */
    {
        oe_result_t result =
            oe_call_enclave(enclave, "TestOCallEdgeCases", NULL);

        OE_TEST(result == OE_OK);
        OE_TEST(_funcACalled);
    }

    /* Call TestReentrancy() */
    {
        _enclave = enclave;
        oe_result_t result = oe_call_enclave(enclave, "TestReentrancy", NULL);

        OE_TEST(result == OE_OK);
        OE_TEST(_reentrancyTested);
    }
    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
