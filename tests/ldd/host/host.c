// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include "ldd_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t* enclave = NULL;
    int return_val = -1;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_ldd_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    result = test_enclave(enclave, &return_val);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);
    if (return_val != 0)
        oe_put_err("%d tests failed in test_enclave()", return_val);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (ldd)\n");

    return 0;
}
