// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>

/* Calling this forces symbols to be available to subsequently linked libs. */
const void* oe_link_core(void)
{
    static const void* symbols[] = {
        oe_sbrk,
    };

    return symbols;
}
