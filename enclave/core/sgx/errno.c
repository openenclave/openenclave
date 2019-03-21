// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

static __thread int _oe_errno = 0;

int* __oe_errno_location(void)
{
    return &_oe_errno;
}
