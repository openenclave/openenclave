// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/types.h>
#include "mixed_u.h"

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

    result = oe_create_mixed_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %s\n", argv[0], argv[1]);
        return 1;
    }

    OE_TEST(foo_c(enclave, 1) == OE_OK);
    OE_TEST(foo_cpp(enclave, 2) == OE_OK);

    oe_terminate_enclave(enclave);

    return 0;
}
