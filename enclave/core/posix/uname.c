// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/internal/trace.h>
#include "oe_t.h"

int oe_uname(struct oe_utsname* buf)
{
    int ret = -1;
    oe_result_t result = OE_FAILURE;

    if ((result = oe_posix_uname_ocall(
             &ret, (struct utsname*)buf, &oe_errno)) != OE_OK)
    {
        OE_TRACE_ERROR("%s", oe_result_str(result));
        goto done;
    }

done:

    return ret;
}
