// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include "set_enclave_log_level_t.h"

void enc_log_test(const char* log_level_str)
{
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_INFO,
            "[Enclave] host_log_level=%s, message log_level=INFO\n",
            log_level_str) == OE_OK);
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_WARNING,
            "[Enclave] host_log_level=%s, message log_level=WARN\n",
            log_level_str) == OE_OK);
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_ERROR,
            "[Enclave] host_log_level=%s, message log_level=ERROR\n",
            log_level_str) == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */

#define TA_UUID                                            \
    { /* c6d845e1-5fd6-4faf-9c73-d84e25d48fe0 */           \
        0xc6d845e1, 0x5fd6, 0x4faf,                        \
        {                                                  \
            0x9c, 0x73, 0xd8, 0x4e, 0x25, 0xd4, 0x8f, 0xe0 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "set_enclave_log_level test")
