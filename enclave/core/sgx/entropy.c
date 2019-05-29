// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/entropy.h>
#include <openenclave/internal/rdrand.h>

/* TODO: This should use RDSEED instead. See issue #242. */
oe_result_t oe_get_entropy(void* output, size_t len)
{
    oe_result_t ret = OE_UNEXPECTED;
    unsigned char* p = (unsigned char*)output;

    if (!output)
        goto done;

    /* Copy 64-bit random integers to output */
    {
        size_t n = len / sizeof(uint64_t);

        while (n--)
        {
            uint64_t x = oe_rdrand();

            if (oe_memcpy_s(p, len, &x, sizeof(uint64_t)) != OE_OK)
                goto done;

            p += sizeof(uint64_t);
            len -= sizeof(uint64_t);
        }
    }

    /* Copy remaining random bytes to output */
    {
        size_t r = len % sizeof(uint64_t);
        uint64_t x = oe_rdrand();
        const unsigned char* q = (const unsigned char*)&x;

        if (oe_memcpy_s(p, len, q, r) != OE_OK)
            goto done;
    }

    ret = OE_OK;

done:
    return ret;
}
