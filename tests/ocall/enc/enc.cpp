// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/elibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include "../args.h"

OE_ECALL void Test2(void* args_)
{
#if 0
    *((int*)0) = 0;
#endif
    Test2Args* args = (Test2Args*)args_;
    args->out = args->in;
}

OE_ECALL void Test4(void* args)
{
    unsigned char buf[32];
    OE_UNUSED(args);

    /* Call into host with enclave memory */
    memset(buf, 0xAA, sizeof(buf));

    if (oe_call_host("Func2", buf) != OE_OK)
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
    char* str = (char*)data;

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

OE_ECALL void SetTSD(void* args_)
{
    SetTSDArgs* args = (SetTSDArgs*)args_;

    if (!args)
        oe_abort();

    /* Initialize this the first time */
    if (oe_once(&_once, _init) != 0)
    {
        args->ret = -1;
        return;
    }

    /* Set the thread-specific data */
    if (oe_thread_setspecific(_key, args->value) != 0)
    {
        args->ret = -1;
        return;
    }

    args->ret = 0;
}

OE_ECALL void GetTSD(void* args_)
{
    GetTSDArgs* args = (GetTSDArgs*)args_;

    if (!args)
        oe_abort();

    args->value = oe_thread_getspecific(_key);
    args->ret = 0;
}

OE_ECALL void was_destructor_called(void* args_)
{
    was_destructor_called_args_t* args = (was_destructor_called_args_t*)args_;

    if (!args)
        oe_abort();

    args->called = _destructor_called;
}

OE_ECALL void TestMyOCall(void* args_)
{
    TestMyOCallArgs* args = (TestMyOCallArgs*)args_;

    if (args)
    {
        my_ocall_args_t* a =
            (my_ocall_args_t*)oe_host_calloc(1, sizeof(my_ocall_args_t));
        a->in = 1000;
        a->out = 0;
        oe_result_t result = oe_call_host("my_ocall", a);
        OE_TEST(result == OE_OK);
        args->result = a->out;
        oe_host_free(a);
    }

    /* Test low-level OCALL of illegal function number */
    {
        oe_result_t result = oe_ocall(0xffff, 0, NULL);
        OE_TEST(result == OE_NOT_FOUND);
    }
}

OE_ECALL void TestOCallEdgeCases(void* args_)
{
    oe_result_t result;
    OE_UNUSED(args_);

    /* Null OCALL. */
    result = oe_call_host(NULL, NULL);
    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Empty OCALL. */
    result = oe_call_host("", NULL);
    OE_TEST(result == OE_NOT_FOUND);

    /* Single letter OCALL. */
    result = oe_call_host("A", NULL);
    OE_TEST(result == OE_OK);

    /* OCALL doesn't exist. */
    result = oe_call_host("B", NULL);
    OE_TEST(result == OE_NOT_FOUND);
}

OE_ECALL void test_callback(void* arg)
{
    test_callback_args_t* args = (test_callback_args_t*)arg;

    if (args && args->callback)
    {
        /* Invoke the host function at the given address */
        oe_result_t result = oe_call_host_by_address(args->callback, args);
        OE_TEST(result == OE_OK);
    }
}

OE_ECALL void TestReentrancy(void* args)
{
    oe_result_t result;
    OE_UNUSED(args);

    result = oe_call_host("TestReentrancy", NULL);
    OE_TEST(result == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
