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
    true, /* Debug */
    1024, /* NumHeapPages */
    256,  /* NumStackPages */
    4);   /* NumTCS */

#define TA_UUID                                            \
    { /* e229cc0f-3199-4ad3-91a7-47906fcbcc59 */           \
        0xe229cc0f, 0x3199, 0x4ad3,                        \
        {                                                  \
            0x91, 0xa7, 0x47, 0x90, 0x6f, 0xcb, 0xcc, 0x59 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "Ping-Pong Shared test")
