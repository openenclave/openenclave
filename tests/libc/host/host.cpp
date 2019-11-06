// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "libc_u.h"

#if defined(_WIN32) && (defined(__x86_64__) || defined(_M_X64))
#define XMM_OK
#endif

#if defined(XMM_OK)
#include <xmmintrin.h>

uint32_t my_getmxcsr()
{
    uint32_t csr;

    csr = _mm_getcsr();
    return csr;
}

void my_setmxcsr(uint32_t csr)
{
    _mm_setcsr(csr);
}

#endif

void Test(oe_enclave_t* enclave)
{
    int rval = 1;
    oe_result_t result = test(enclave, &rval);
    OE_TEST(result == OE_OK);

    if (rval == 0)
    {
        printf("=== passed\n");
    }
    else
    {
        printf("*** failed\n");
        abort();
    }
}

void ocall_exit(uint64_t arg)
{
    exit(static_cast<int>(arg));
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    oe_result_t result;
    const uint32_t flags = oe_get_create_flags();

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);

#if defined(XMM_OK)
    volatile uint32_t csr;
    csr = my_getmxcsr();
    OE_TEST(csr == 0x1f80);
#endif

    // Create the enclave:
    if ((result = oe_create_libc_enclave(
             argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_libc_enclave(): result=%u", result);

#if defined(XMM_OK)
    csr = my_getmxcsr();
    OE_TEST(csr == 0x1f80);
#endif

    Test(enclave);

#if defined(XMM_OK)
    csr = my_getmxcsr();
    OE_TEST(csr == 0x1f80);
#endif

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
