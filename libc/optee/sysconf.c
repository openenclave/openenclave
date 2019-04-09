// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>

long sysconf(int name)
{
    (void)name;

    /* 2^x, where x is quite random indeed. */
    return 8;
}
