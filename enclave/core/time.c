// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openenclave/bits/time.h"
#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/time.h>
#include "openenclave/bits/result.h"

uint64_t oe_get_time(void)
{
    uint64_t ret = (uint64_t)-1;

    if (oe_ocall(OE_OCALL_GET_TIME, 0, &ret) != OE_OK)
    {
        ret = (uint32_t)-1;
        goto done;
    }

done:

    return ret;
}

static oe_result_t oe_syscall_clock_gettime_ocall_stub(
    int* ret,
    oe_clockid_t clockid,
    oe_timespec* ts)
{
    *ret = -1;
    OE_UNUSED(clockid);
    OE_UNUSED(ts);
    static bool once = false;
    if (!once)
    {
        once = true;
        OE_TRACE_INFO("Add the following to your edl to enable different "
                      "clockids in clock_gettime syscall:\n"
                      "\n"
                      "from \"openenclave/edl/time.edl\" import "
                      "oe_syscall_clock_gettime_ocall;\n"
                      "\n");
    }
    return OE_UNSUPPORTED;
}

OE_WEAK_ALIAS(
    oe_syscall_clock_gettime_ocall_stub,
    oe_syscall_clock_gettime_ocall);
