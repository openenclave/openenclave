// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "create_rapid_t.h"

int test(int arg)
{
    return arg * 2;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */

#define TA_UUID                                            \
    { /* 688ab13f-5bc0-40af-8dc6-01d007fd2210 */           \
        0x688ab13f, 0x5bc0, 0x40af,                        \
        {                                                  \
            0x8d, 0xc6, 0x01, 0xd0, 0x07, 0xfd, 0x22, 0x10 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "Create Rapid test")
