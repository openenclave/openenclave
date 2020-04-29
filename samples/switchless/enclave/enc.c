// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include "switchless_t.h"

void enclave_add_N_switchless(int* m, int n)
{
    // Call back into the host switchlessly
    for (int i = 0; i < n; i++)
    {
        oe_result_t result = host_increment_switchless(m);
        if (result != OE_OK)
        {
            fprintf(stderr, "host_increment_switchless(): result=%u", result);
        }
    }
}

void enclave_add_N_regular(int* m, int n)
{
    // Call back into the host
    for (int i = 0; i < n; i++)
    {
        oe_result_t result = host_increment_regular(m);
        if (result != OE_OK)
        {
            fprintf(stderr, "host_increment_regular(): result=%u", result);
        }
    }
}

void enclave_decrement_switchless(int* n)
{
    *n = *n - 1;
}

void enclave_decrement_regular(int* n)
{
    *n = *n - 1;
}
