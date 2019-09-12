// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>

#include "../common/multiply.h"
#include "matrix_t.h"

void enclave_matrix()
{
    fprintf(stdout, "Hello from the enclave\n");

    // Do task
    task();

    // Call back into the host
    oe_result_t result = host_matrix();
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "Call to host_matrix failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
}
