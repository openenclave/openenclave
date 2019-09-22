// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include "switchless_t.h"

void enclave_helloworld()
{
    fprintf(stdout, "Hello world from the enclave\n");

    // Call back into the host
    oe_result_t result = host_helloworld();
    if (result != OE_OK)
    {
        fprintf(stderr, "host_helloworld(): result=%u", result);
    }

    result = host_helloworld_switchless();
    if (result != OE_OK)
    {
        fprintf(stderr, "host_helloworld_switchless(): result=%u", result);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
