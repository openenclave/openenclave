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

extern "C" OE_NEVER_INLINE void GetBacktrace(Backtrace* b)
{
    b->size = oe_backtrace(b->buffer, OE_COUNTOF(b->buffer));

    /* Check for truncation */
    OE_TEST(b->size < (int)OE_COUNTOF(b->buffer));
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

static void _print_backtrace(
    void* const* buffer,
    int size,
    int num_expected_symbols,
    const char* expected_symbols[])
{
/* Backtrace does not work in release mode */
#ifndef NDEBUG

    char** symbols = oe_backtrace_symbols(buffer, size);
    OE_TEST(symbols != NULL);

    oe_host_printf("=== backtrace:\n");

    for (int i = 0; i < size; i++)
        oe_host_printf("%s(): (%p)\n", symbols[i], buffer[i]);

    OE_TEST(size == num_expected_symbols);

    for (int i = 0; i < size; i++)
        OE_TEST(strcmp(expected_symbols[i], symbols[i]) == 0);

    oe_host_printf("\n");

    oe_host_free(symbols);

#endif
}

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;

    oe_host_printf("=== Test()\n");

    Backtrace b;
    GetBacktrace(&b);

    OE_TEST(b.size > 0);

    char** syms = oe_backtrace_symbols(b.buffer, b.size);
    OE_TEST(syms != NULL);

    _print_backtrace(b.buffer, b.size, args->num_syms, args->syms);

    args->okay = true;
}

OE_ECALL void TestUnwind(void* args_)
{
    Args* args = (Args*)args_;

    oe_host_printf("=== TestUnwind()\n");

    try
    {
        func1(args);
    }
    catch (Backtrace& b)
    {
        char** syms = oe_backtrace_symbols(b.buffer, b.size);
        OE_TEST(syms != NULL);

        _print_backtrace(b.buffer, b.size, args->num_syms, args->syms);
        args->okay = true;
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
