// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/corelibc/errno.h>

static __thread _errno;

int* __oe_errno_location(void)
{
    return &_errno;
}
