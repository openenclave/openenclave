// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
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
    OE_Memset(buf, 0xAA, sizeof(buf));

    if (OE_CallHost("Func2", buf) != OE_OK)
    {
        OE_Abort();
        return;
    }
}

static OE_OnceType _once = OE_ONCE_INITIALIZER;
static OE_ThreadKey _key = OE_THREADKEY_INITIALIZER;

static void _init()
{
    if (OE_ThreadKeyCreate(&_key, NULL) != 0)
        OE_Abort();
}

OE_ECALL void SetTSD(void* args_)
{
    SetTSDArgs* args = (SetTSDArgs*)args_;

    if (!args)
        OE_Abort();

    /* Initialize this the first time */
    if (OE_Once(&_once, _init) != 0)
    {
        args->ret = -1;
        return;
    }

    /* Set the thread-specific data */
    if (OE_ThreadSetSpecific(_key, args->value) != 0)
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
        OE_Abort();

    args->value = OE_ThreadGetSpecific(_key);
    args->ret = 0;
}

OE_ECALL void TestMyOCall(void* args_)
{
    TestMyOCallArgs* args = (TestMyOCallArgs*)args_;

    if (args)
    {
        OE_Result result = OE_OCall(0, 1000, &args->result, 0);
        OE_TEST(result == OE_OK);
    }
}
