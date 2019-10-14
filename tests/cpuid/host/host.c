// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <cpuid.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "cpuid_u.h"

#define SKIP_RETURN_CODE 2

void cpuid_ocall(
    uint32_t leaf,
    uint32_t subleaf,
    uint32_t* eax,
    uint32_t* ebx,
    uint32_t* ecx,
    uint32_t* edx)
{
    if (eax)
        *eax = 0;

    if (ebx)
        *ebx = 0;

    if (ecx)
        *ecx = 0;

    if (edx)
        *edx = 0;

    __cpuid_count(leaf, subleaf, *eax, *ebx, *ecx, *edx);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();

    // In simulation mode cpuid instruction will just be successfully executed
    // on the host and the exception handler will not be called.
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = oe_create_cpuid_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    result = test_cpuid(enclave);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (cpuid)\n");

    return 0;
}
