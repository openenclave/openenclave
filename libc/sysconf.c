// Copyright (c) Open Enclave SDK contributors.
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
