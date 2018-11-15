// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/oelog.h>

OE_ECALL void Test(void* args_)
{
    oe_result_t ret = oe_log_trace("test", "this is %s%d", "test", 1);

    /* Check for return code */
    OE_TEST(ret == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
