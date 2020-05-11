// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_OCALL_OPTOUT_H
#define _OE_OCALL_OPTOUT_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

#ifdef OE_SWITCHLESS_OPT_OUT
void oe_sgx_wake_switchless_worker_ocall(void* context)
{
    OE_UNUSED(context);
    return;
}

void oe_sgx_sleep_switchless_worker_ocall(void* context)
{
    OE_UNUSED(context);
    return;
}
#endif

OE_EXTERNC_END

#endif // _OE_OCALL_OPTOUT_H
