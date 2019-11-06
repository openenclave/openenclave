// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>

#include "all_u.h"

int ocall_sum(int a, int b)
{
    return a + b;
}

int switchless_ocall_sum(int a, int b)
{
    return a + b;
}
