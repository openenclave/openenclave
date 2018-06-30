// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/corelibc/string.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
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

    /* Call into host with enclave memory */
    oe_memset(buf, 0xAA, sizeof(buf));

    if (oe_call_host("Func2", buf) != OE_OK)
    {
        oe_abort();
        return;
    }
}

static oe_once_t _once = OE_ONCE_INITIALIZER;
static oe_thread_key_t _key = OE_THREADKEY_INITIALIZER;

static void _init()
{
    if (oe_thread_key_create(&_key, NULL) != 0)
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
    if (oe_thread_set_specific(_key, args->value) != 0)
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

    args->value = oe_thread_get_specific(_key);
    args->ret = 0;
}

OE_ECALL void TestMyOCall(void* args_)
{
    TestMyOCallArgs* args = (TestMyOCallArgs*)args_;

    if (args)
    {
        oe_result_t result = oe_ocall(0, 1000, &args->result, 0);
        OE_TEST(result == OE_OK);
    }
}
