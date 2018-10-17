// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>

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

    result = oe_create_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %s\n", argv[0], argv[1]);
        return 1;
    }

    int return_value = INT_MIN;
    if ((result = oe_call_enclave(enclave, "Test", &return_value)) != OE_OK)
    {
        fprintf(stderr, "%s: ecall failed: result=%u\n", argv[0], result);
        return 1;
    }

    if (return_value != 0)
    {
        fprintf(stderr, "ecall failed: returnValue=%d\n", return_value);
        return 1;
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (SampleAppCRTHost)\n");

    return 0;
}
