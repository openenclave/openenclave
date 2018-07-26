// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "../args.h"

struct Backtrace
{
    void* buffer[MAX_ADDRESSES];
    int size;
};

extern "C" OE_NEVER_INLINE void GetBacktrace(Args* args)
{
    args->size = oe_backtrace(args->buffer, OE_COUNTOF(args->buffer));

    /* Check for truncation */
    OE_TEST(args->size < (int)OE_COUNTOF(args->buffer));
}

extern "C" OE_NEVER_INLINE void func4(Args* args)
{
    Backtrace b;

    b.size = oe_backtrace(b.buffer, OE_COUNTOF(b.buffer));

    /* Check for truncation */
    OE_TEST(b.size < (int)OE_COUNTOF(b.buffer));

    throw(b);
}

extern "C" OE_NEVER_INLINE void func3(Args* args)
{
    func4(args);
}

extern "C" OE_NEVER_INLINE void func2(Args* args)
{
    func3(args);
}

extern "C" OE_NEVER_INLINE void func1(Args* args)
{
    func2(args);
}

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;

    if (args)
        GetBacktrace(args);
}

OE_ECALL void TestUnwind(void* args_)
{
    Args* args = (Args*)args_;

    memset(args, 0, sizeof(Args));

    try
    {
        func1(args);
    }
    catch (Backtrace& b)
    {
        memcpy(args->buffer, b.buffer, sizeof(args->buffer));
        args->size = b.size;
    }
}
