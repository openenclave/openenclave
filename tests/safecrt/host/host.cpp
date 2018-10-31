// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

#include "../common/test.h"
#include "safecrt_u.h"

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

    result = oe_create_safecrt_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    // Test enclave safecrt
    printf("=== running enclave tests (safecrt)\n");
    OE_TEST(enc_test_memcpy_s(enclave) == OE_OK);
    OE_TEST(enc_test_memmove_s(enclave) == OE_OK);
    OE_TEST(enc_test_strncpy_s(enclave) == OE_OK);
    OE_TEST(enc_test_strncat_s(enclave) == OE_OK);
    OE_TEST(enc_test_memset_s(enclave) == OE_OK);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    // Test host safecrt
    printf("=== running host tests (safecrt)\n");
    test_memcpy_s();
    test_memmove_s();
    test_strncpy_s();
    test_strncat_s();
    test_memset_s();

    printf("=== passed all tests (safecrt)\n");

    return 0;
}
