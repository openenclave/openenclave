// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef USE_ENTROPY_EDL
#include "symcrypt_provider_u.h"
#else
#include "symcrypt_provider_no_entropy_u.h"
#endif

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

#ifdef USE_ENTROPY_EDL
    result = oe_create_symcrypt_provider_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    result = ecall_test(enclave);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (symcrypt_provider)\n");
#else
    result = oe_create_symcrypt_provider_no_entropy_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_ENCLAVE_ABORTING);

    printf("=== passed all tests (symcrypt_provider_no_entropy)\n");
#endif

    return 0;
}
