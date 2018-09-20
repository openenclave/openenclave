// Copyright (c) Microsoft Corporation. All rights reserved.
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
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
