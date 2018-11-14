// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/log.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <string.h>

extern "C" OE_NEVER_INLINE void GetLog()
{
    oe_result_t ret = oe_send_log("test", "this is %s%d", "test", 1);

    /* Check for return code */
    OE_TEST(ret == OE_OK);
}

OE_ECALL void Test(void* args_)
{
    GetLog();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
