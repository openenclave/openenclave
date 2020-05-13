// Copyright (c) Open Enclave SDK contributors.
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
    true, /* Debug */
    8,    /* NumHeapPages */
    8,    /* NumStackPages */
    1);   /* NumTCS */

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
    0,
    "1.0.0",
    "Create Rapid test")
