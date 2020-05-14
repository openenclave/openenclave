// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/hexdump.h>
#include "hexdump_t.h"

int test(
    const unsigned char* data,
    size_t data_length,
    char* hexstr,
    size_t hexstr_length)
{
    oe_hex_dump(data, data_length);

    const char* str = oe_hex_string(hexstr, hexstr_length, data, data_length);

    if (str != hexstr)
    {
        return -1;
    }

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */

#define TA_UUID                                            \
    { /* 126830b9-eb9f-412a-89a7-bcc8a517c12e */           \
        0x126830b9, 0xeb9f, 0x412a,                        \
        {                                                  \
            0x89, 0xa7, 0xbc, 0xc8, 0xa5, 0x17, 0xc1, 0x2e \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "Hexdump test")
