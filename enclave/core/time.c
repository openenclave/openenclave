// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/time.h>

int oe_sleep(uint64_t milliseconds)
{
    size_t ret = -1;
    const uint32_t flags = OE_OCALL_FLAG_NOT_REENTRANT;

    if (oe_ocall(OE_OCALL_SLEEP, milliseconds, NULL, flags) != OE_OK)
        goto done;

    ret = 0;

done:

    return ret;
}

uint64_t oe_get_time(void)
{
    uint64_t ret = 0;
    const uint32_t flags = OE_OCALL_FLAG_NOT_REENTRANT;

    if (oe_ocall(OE_OCALL_GET_TIME, 0, &ret, flags) != OE_OK)
    {
        ret = 0;
        goto done;
    }

done:

    return ret;
}
