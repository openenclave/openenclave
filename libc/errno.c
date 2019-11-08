// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>

int* __errno_location(void)
{
    return __oe_errno_location();
}

/* MUSL also needs a definition with a triple-underscore. */
int* ___errno_location(void)
{
    return __oe_errno_location();
}
