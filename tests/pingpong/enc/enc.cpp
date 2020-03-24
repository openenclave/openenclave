// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "pingpong_t.h"

void Ping(const char* in, char* out, int out_length)
{
    Pong(in, out, out_length);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */

#define TA_UUID                                            \
    { /* 0a6cbbd3-160a-4c86-9d9d-c9cf1956be16 */           \
        0x0a6cbbd3, 0x160a, 0x4c86,                        \
        {                                                  \
            0x9d, 0x9d, 0xc9, 0xcf, 0x19, 0x56, 0xbe, 0x16 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "Ping-Pong test")
