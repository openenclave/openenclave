// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>

static OE_THREAD_LOCAL_STORAGE int _errno = 0;

int* __oe_errno_location(void)
{
    return &_errno;
}
