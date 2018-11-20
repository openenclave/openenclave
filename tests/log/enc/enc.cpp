// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/oelog.h>

OE_ECALL void Test(void* args_)
{
    oe_result_t ret;
    ret = oe_log(OE_LOG_FLAGS_ATTESTATION, OE_LOG_INFO, "test%d: %s/%s is ON", 1, "OE_LOG_FLAGS_ATTESTATION", "OE_LOG_INFO");
    OE_TEST(ret == OE_OK);
    ret = oe_log(OE_LOG_FLAGS_COMMON, OE_LOG_ERROR, "test%d: %s/%s is ON", 2, "OE_LOG_FLAGS_COMMON", "OE_LOG_ERROR");
    OE_TEST(ret == OE_OK);
    ret = oe_log(OE_LOG_FLAGS_TOOLS, OE_LOG_INFO, "test%d: %s/%s is OFF", 3, "OE_LOG_FLAGS_TOOLS", "OE_LOG_INFO");
    OE_TEST(ret == OE_OK);
    ret = oe_log(OE_LOG_FLAGS_ATTESTATION, OE_LOG_DEBUG, "test%d: %s/%s is OFF", 4, "OE_LOG_FLAGS_ATTESTATION", "OE_LOG_DEBUG");
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
