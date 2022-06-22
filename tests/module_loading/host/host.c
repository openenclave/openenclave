// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "module_loading_u.h"

int enclave_fini;
int module_fini;

void notify_enclave_done()
{
    enclave_fini = 1;
}

void notify_module_done()
{
    module_fini = 1;
}

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

    if ((result = oe_create_module_loading_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    result = enc_module_test(enclave);

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    OE_TEST(enclave_fini == 1);
    OE_TEST(module_fini == 1);

    printf("=== passed all tests (module_loading)\n");

    return 0;
}
