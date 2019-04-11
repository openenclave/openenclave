// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>

#include <openenclave/internal/print.h>
#include "switchless_t.h"

int standard_enc_sum(int arg1, int arg2)
{
    // oe_host_printf("      <standard_enc_sum/> %d + %d = %d\n", arg1, arg2,
    //                arg1 + arg2);

    return arg1 + arg2;
}

int synchronous_switchless_enc_sum(int arg1, int arg2)
{
    // oe_host_printf("      </synchronous_switchless_enc_sum>\n");

    return arg1 + arg2;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    16,   /* StackPageCount */
    16);  /* TCSCount */
