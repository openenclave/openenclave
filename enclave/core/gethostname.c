// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/corelibc/unistd.h>

int oe_gethostname(char* name, size_t len)
{
    int ret = -1;
    struct oe_utsname uts;

    if (oe_uname(&uts) != 0)
        goto done;

    oe_strlcpy(name, uts.nodename, len);
    ret = 0;

done:
    return ret;
}
