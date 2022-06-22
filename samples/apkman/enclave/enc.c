// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sqlite_t.h"

int main();

int enc_main()
{
    return main();
}

// This will be overridden during signing by sqlite.conf.
OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    256,  /* NumHeapPages: 1 MB */
    16,   /* NumStackPages: 64 KB */
    2);   /* NumTCS */

#define TA_UUID                                            \
    { /* 4d5d6469-e571-4619-aefe-cc28d839f367 */           \
        0x4d5d6469, 0xe571, 0x4619,                        \
        {                                                  \
            0xae, 0xfe, 0xcc, 0x28, 0xd8, 0x39, 0xf3, 0x67 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    /* 1 MB heap */
    1 * 1024 * 1024,
    16 * 1024,
    0,
    "1.0.0",
    "sqlite sample")
