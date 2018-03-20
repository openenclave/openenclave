// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/enclavelibc.h>
#include <openenclave/enclave.h>

uint64_t _rdrand(void)
{
    uint64_t r;
    __asm__ volatile(
        "rdrand %%rax\n\t"
        "mov %%rax, %0\n\t"
        : "=m"(r)
        :
        : "rax");

    return r;
}

/*
 * MBEDTLS links this function defintion when MBEDTLS_ENTROPY_HARDWARE_ALT
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

            OE_Memcpy(p, &x, sizeof(uint64_t));
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
