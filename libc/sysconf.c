// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/enclave.h>
#include <unistd.h>

long sysconf(int name)
{
    OE_UNUSED(name);
    errno = EINVAL;
    return -1;
}
