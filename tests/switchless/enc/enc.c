// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/edger8r/switchless.h>
#include <openenclave/internal/tests.h>
#include "switchless_t.h"

int standard_enc_sum(int arg1, int arg2)
{
    return arg1 + arg2;
}

int synchronous_switchless_enc_sum(int arg1, int arg2)
{
    return arg1 + arg2;
}

void batch_enc_sum(addition_args* args, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        args[i].sum = args[i].arg1 + args[i].arg2;
    }
}

int enc_test(
    oe_switchless_t* switchless,
    int type,
    addition_args* args,
    size_t count)
{
    if (NULL == switchless)
    {
        return 1;
    }

    if (1 == type)
    {
        for (size_t i = 0; i < count; ++i)
        {
            OE_TEST(OE_OK == standard_host_sum(
                        &(args[i].sum), args[i].arg1, args[i].arg2));
        }
    }
    else if (2 == type)
    {
        if (NULL != switchless)
        {
            for (size_t i = 0; i < count; ++i)
            {
                OE_TEST(OE_OK == synchronous_switchless_host_sum(
#if _USE_SWITCHLESS
                            switchless,
#endif
                            &(args[i].sum), args[i].arg1, args[i].arg2));
            }
        }
    }
    else if (3 == type)
    {
        OE_TEST(OE_OK == batch_host_sum(args, count));
    }

    return OE_OK;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
