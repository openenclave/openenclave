// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "test_u.h"

int main(int argc, char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    int return_val;
    bool decompress = false;

    if (argc != 5 && argc != 3)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH -d/-c [source destination]\n",
            argv[0]);
        return 1;
    }

    decompress = strcmp(argv[2], "-d") == 0;

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_test_enclave(
             argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    result = enc_test(
        enclave,
        &return_val,
        decompress,
        (argc == 5 ? argv[3] : NULL),
        (argc == 5 ? argv[4] : NULL));

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (return_val != 0)
        oe_put_err("ECALL failed args.result=%d", return_val);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("passed all tests (zlib)\n");

    return 0;
}
