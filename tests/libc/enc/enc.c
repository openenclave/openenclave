// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "helpers.h"
#include "libc_t.h"

int test()
{
    return run_tests();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    512,  /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */

#define TA_UUID                                            \
    { /* d7fe296a-24e9-46d1-aa78-9c7395082a41 */           \
        0xd7fe296a, 0x24e9, 0x46d1,                        \
        {                                                  \
            0xaa, 0x78, 0x9c, 0x73, 0x95, 0x08, 0x2a, 0x41 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "libc test")
