// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <list>
#include "mixed_t.h"

void foo_cpp(int a)
{
    OE_UNUSED(a);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    256,  /* NumStackPages */
    4);   /* NumTCS */

#define TA_UUID                                            \
    { /* 952c55c8-59f3-47a0-814c-ae3276a9808f */           \
        0x952c55c8, 0x59f3, 0x47a0,                        \
        {                                                  \
            0x81, 0x4c, 0xae, 0x32, 0x76, 0xa9, 0x80, 0x8f \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "Mixed C/C++ test")
