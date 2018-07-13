// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

OE_NEVER_INLINE void GetBacktrace(Args* args)
{
    args->size = OE_COUNTOF(args->buffer);
    args->size = oe_backtrace(args->buffer, args->size);
}

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;

    if (args)
        GetBacktrace(args);
}
