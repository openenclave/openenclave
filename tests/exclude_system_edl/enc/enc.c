// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <time.h>

#include "exclude_system_edl_t.h"

void enc_nanosleep()
{
    // Since nanosleep makes an ocall, we will need to include
    // the proper ocall in our EDL file.
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 100;
    nanosleep(&t, &t);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */

#define TA_UUID                                            \
    { /* b07e2f2c-b911-48d3-8c4f-a29831d604d2 */           \
        0xb07e2f2c, 0xb911, 0x48d3,                        \
        {                                                  \
            0x8c, 0x4f, 0xa2, 0x98, 0x31, 0xd6, 0x04, 0xd2 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "Exclude System EDL test")
