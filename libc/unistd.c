// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <unistd.h>

long sysconf(int name)
{
    errno = EINVAL;
    return -1;
}
