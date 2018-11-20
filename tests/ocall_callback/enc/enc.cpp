// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include "../args.h"

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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
