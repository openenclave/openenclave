// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

static int _errno = 0; // We do this because a TA has only one thread

int* __oe_errno_location(void)

{
    return &_errno;
}
