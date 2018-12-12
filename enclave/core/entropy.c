// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include "../../common/common.h"

/*
 * MBEDTLS links this function definition when MBEDTLS_ENTROPY_HARDWARE_ALT
 * is defined in the MBEDTLS config.h file. This is the sole source of entropy
 * for MBEDTLS. All other MBEDTLS entropy sources are disabled since they don't
 * work within enclaves.
 */
int mbedtls_hardware_poll(
    void* data,
    unsigned char* output,
    size_t len,
    size_t* olen)
{
    int ret = -1;
    unsigned char* p = output;

    OE_UNUSED(data);

    if (!output)
        goto done;

    /* Copy 64-bit random integers to output */
    {
        size_t n = len / sizeof(uint64_t);

        while (n--)
        {
            uint64_t x = _rdrand();

            if (oe_memcpy_s(p, sizeof(uint64_t), &x, sizeof(uint64_t)) != OE_OK)
                goto done;

            p += sizeof(uint64_t);
        }
    }

    /* Copy remaining random bytes to output */
    {
        size_t r = len % sizeof(uint64_t);
        uint64_t x = _rdrand();
        const unsigned char* q = (const unsigned char*)&x;

        while (r--)
            *p++ = *q++;
    }

    if (olen)
        *olen = len;

    ret = 0;

done:
    return ret;
}
