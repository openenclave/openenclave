// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/sgx/td.h>

int* __oe_errno_location(void)
{
    return &oe_sgx_get_td()->errnum;
}
