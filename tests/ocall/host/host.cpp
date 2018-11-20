// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "ocall_u.h"

static bool _func1_called = false;

void func1(void)
{
    _func1_called = true;
}

uint64_t my_ocall(uint64_t in)
{
    return in * 7;
}

static bool _func2_ok = false;

void func2(void)
{
    _func2_ok = true;
}

static bool _func_a_called = false;

void a(void)
{
    _func_a_called = true;
}

static oe_enclave_t* _enclave = NULL;
static bool _reentrancy_tested = false;

void test_reentrancy_ocall(void)
{
    // misspelled functions are caught by the host.
    oe_result_t result = oe_call_enclave(_enclave, "foobar", NULL);
    OE_TEST(result == OE_NOT_FOUND);
    
    // Valid function; but reentrant call.
    result = test_reentrancy_ecall(_enclave);
    printf("result ==== %s\n", oe_result_str(result));
    OE_TEST(result == OE_REENTRANT_ECALL);

    _reentrancy_tested = true;
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
    result = oe_create_ocall_enclave (
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
        oe_put_err("oe_create_ocall_enclave(): result=%u", result);

    /* Call Test2() */
    {
        int64_t in = 123456789;
        int64_t out = 0;
        result = test2(enclave, &out, in);
        OE_TEST(result == OE_OK);
        OE_TEST(out == in);
    }

    /* Call Test4() */
    {
        result = test4(enclave);
        OE_TEST(result == OE_OK);
        OE_TEST(_func2_ok);
    }

    /* Call was_destructor_called() */
    {
        bool retval = true;
        result = was_destructor_called(enclave, &retval);
        OE_TEST(result == OE_OK);
        OE_TEST(retval == false);
    }

    /* Call set_tsd() */
    {
        void* value = strdup("TSD-DATA");
        int retval = 0;
        result = set_tsd(enclave, &retval, value);
        OE_TEST(result == OE_OK);
    }

    /* Call was_destructor_called() */
    {
        bool retval = false;
        result = was_destructor_called(enclave, &retval);
        OE_TEST(result == OE_OK);
        OE_TEST(retval == true);
    }

    /* Call get_tsd() */
    {
        void* value = nullptr;
        int retval = 0;
        result = get_tsd(enclave, &retval, value);
        OE_TEST(result == OE_OK);
        /* Returning from set_tsd() cleared this TSD slot */
        OE_TEST(value == NULL);
    }

    /* Call TestMyOCall() */
    {
        uint64_t retval = 0;
        result = test_my_ocall(enclave, &retval);
        OE_TEST(result == OE_OK);
        OE_TEST(retval == 7000);
    }

    /* Call TestOCallEdgeCases() */
    {
        result = test_ocall_edge_cases(enclave);
        OE_TEST(result == OE_OK);
        OE_TEST(_func_a_called);
    }
    
    /* Call TestReentrancy() */
    {
        _enclave = enclave;
        result = test_reentrancy_ecall(enclave);
        OE_TEST(result == OE_OK);
        OE_TEST(_reentrancy_tested);
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
