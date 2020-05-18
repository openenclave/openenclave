// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>

#include "../common/test.h"
#include "safecrt_t.h"

void enc_test_memcpy_s()
{
    test_memcpy_s();
}

void enc_test_memmove_s()
{
    test_memmove_s();
}

void enc_test_strncpy_s()
{
    test_strncpy_s();
}

void enc_test_strncat_s()
{
    test_strncat_s();
}

void enc_test_memset_s()
{
    test_memset_s();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */

#define TA_UUID                                            \
    { /* 91dc6667-7a33-4bbc-ab3e-ab4fca5215b7 */           \
        0x91dc6667, 0x7a33, 0x4bbc,                        \
        {                                                  \
            0xab, 0x3e, 0xab, 0x4f, 0xca, 0x52, 0x15, 0xb7 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "Safe CRT test")
