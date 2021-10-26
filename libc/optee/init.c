// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/libc/init.h>
#include "libc.h"
#include "stdio_impl.h"

void oe_libc_initialize(void)
{
    // No multi-threaded initialization needed for OP-TEE.
}

bool oe_test_libc_is_initialized(void)
{
    return true;
}
