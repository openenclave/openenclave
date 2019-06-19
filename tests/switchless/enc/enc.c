// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
