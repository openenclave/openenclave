// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include "ocall_t.h"

int64_t test2(int64_t in)
{
    return in;
}

void test4(void)
{
    unsigned char buf[32];

    /* Call into host with enclave memory */
    oe_memset(buf, 0xAA, sizeof(buf));

    if (func2() != OE_OK)
    {
        oe_abort();
        return;
    }
}

static oe_once_t _once = OE_ONCE_INIT;
static oe_thread_key_t _key = OE_THREADKEY_INITIALIZER;

static bool _destructor_called = false;

static void _destructor(void* data)
{
    char* str = reinterpret_cast<char*>(data);

    if (oe_strcmp(str, "TSD-DATA") == 0)
    {
        oe_host_free(str);
        _destructor_called = true;
        OE_TEST(oe_thread_setspecific(_key, NULL) == 0);
    }
}

static void _init()
{
    if (oe_thread_key_create(&_key, _destructor) != 0)
        oe_abort();
}

int set_tsd(void* value)
{
    /* Initialize this the first time */
    if (oe_once(&_once, _init) != 0 ||
        oe_thread_setspecific(_key, value) != 0)
    {
        return -1;
    }

    return 0;
}

int get_tsd(void* value)
{
    value = oe_thread_getspecific(_key);
    return 0;
}

bool was_destructor_called()
{
    return _destructor_called;
}

uint64_t test_my_ocall(void)
{
    /* Test low-level OCALL of illegal function number */
    oe_result_t result = oe_ocall(0xffff, 0 , nullptr);
    OE_TEST(result == OE_NOT_FOUND);

    uint64_t retval = 0;
    result = my_ocall(&retval, 1000);
    OE_TEST(result == OE_OK);
    return retval;
}

void test_ocall_edge_cases(void)
{
    oe_result_t result;

    /* Null OCALL. */
    result = oe_call_host(NULL, NULL);
    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Empty OCALL. */
    result = oe_call_host("", NULL);
    OE_TEST(result == OE_NOT_FOUND);

    /* Single letter OCALL. */
    result = oe_call_host("a", NULL);
    OE_TEST(result == OE_OK);

    /* OCALL doesn't exist. */
    result = oe_call_host("b", NULL);
    OE_TEST(result == OE_NOT_FOUND);
}

void test_reentrancy_ecall(void)
{
    oe_result_t result = test_reentrancy_ocall();
    OE_TEST(result == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */
