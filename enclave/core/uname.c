// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>

int oe_uname(struct oe_utsname* buf_out)
{
    int ret = -1;
    struct oe_utsname* buf = NULL;
    uint64_t err = 0;

    if (!buf_out)
    {
        oe_errno = EFAULT;
        goto done;
    }

    if (!(buf = oe_host_calloc(1, sizeof(struct oe_utsname))))
    {
        oe_errno = ENOMEM;
        goto done;
    }

    if (oe_ocall(OE_OCALL_UNAME, (uint64_t)buf, &err) != OE_OK)
        goto done;

    if (err)
    {
        oe_errno = (int)err;
        goto done;
    }

    memcpy(buf_out, buf, sizeof(struct oe_utsname));

    ret = 0;

done:

    if (buf)
        oe_host_free(buf);

    return ret;
}
