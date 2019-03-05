// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>

int* __errno_location(void)
{
    return __oe_errno_location();
}

int* ___errno_location(void)
{
    return __oe_errno_location();
}
