// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "backtrace_t.h"

#define MAX_ADDRESSES 64

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

extern "C" OE_NEVER_INLINE void func4(size_t num_syms, const char** syms)
{
    Backtrace b;

    OE_UNUSED(num_syms);
    OE_UNUSED(syms);

    b.size = oe_backtrace(b.buffer, OE_COUNTOF(b.buffer));

    /* Check for truncation */
    OE_TEST(b.size < (int)OE_COUNTOF(b.buffer));

    throw(b);
}

extern "C" OE_NEVER_INLINE void func3(size_t num_syms, const char** syms)
{
    func4(num_syms, syms);
}

extern "C" OE_NEVER_INLINE void func2(size_t num_syms, const char** syms)
{
    func3(num_syms, syms);
}

extern "C" OE_NEVER_INLINE void func1(size_t num_syms, const char** syms)
{
    func2(num_syms, syms);
}

/* Backtrace does not work in non-debug builds */
#ifdef OE_USE_DEBUG_MALLOC
static void _print_backtrace(
    void* const* buffer,
    size_t size,
    size_t num_expected_symbols,
    const char* expected_symbols[])
{
    char** symbols = oe_backtrace_symbols(buffer, static_cast<int>(size));
    OE_TEST(symbols != NULL);

    oe_host_printf("=== backtrace:\n");

    for (size_t i = 0; i < size; i++)
        oe_host_printf("%s(): (%p)\n", symbols[i], buffer[i]);

    OE_TEST(size == num_expected_symbols);

    for (size_t i = 0; i < size; i++)
        OE_TEST(strcmp(expected_symbols[i], symbols[i]) == 0);

    oe_host_printf("\n");

    oe_backtrace_symbols_free(symbols);
}
#endif

extern "C" bool test(size_t num_syms, const char** syms)
{
    oe_host_printf("=== test()\n");

    Backtrace b;
    GetBacktrace(&b);

    OE_UNUSED(num_syms);
    OE_UNUSED(syms);

/* Backtrace does not work in non-debug builds */
#ifdef OE_USE_DEBUG_MALLOC
    OE_TEST(b.size > 0);

    char** _syms = oe_backtrace_symbols(b.buffer, b.size);
    OE_TEST(_syms != NULL);

    _print_backtrace(b.buffer, (size_t)b.size, num_syms, syms);
#endif

    return true;
}

extern "C" bool test_unwind(size_t num_syms, const char** syms)
{
    oe_host_printf("=== test_unwind()\n");

    try
    {
        func1(num_syms, syms);
    }
    catch (Backtrace& b)
    {
/* backtrace does not work in non-debug builds */
#ifdef OE_USE_DEBUG_MALLOC
        char** _syms = oe_backtrace_symbols(b.buffer, b.size);
        OE_TEST(_syms != NULL);

        _print_backtrace(b.buffer, (size_t)b.size, num_syms, syms);
#endif
        return true;
    }
    return false;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
