// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <execinfo.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
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
    b->size = backtrace(b->buffer, OE_COUNTOF(b->buffer));

    /* Check for truncation */
    OE_TEST(b->size < (int)OE_COUNTOF(b->buffer));
}

extern "C" OE_NEVER_INLINE void func4(size_t num_syms, const char** syms)
{
    Backtrace b;

    OE_UNUSED(num_syms);
    OE_UNUSED(syms);

    b.size = backtrace(b.buffer, OE_COUNTOF(b.buffer));

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

static void _print_backtrace(
    void* const* buffer,
    size_t size,
    size_t num_expected_symbols,
    const char* expected_symbols[])
{
    char** symbols = backtrace_symbols(buffer, static_cast<int>(size));
    OE_TEST(symbols != NULL);

    oe_host_printf("=== backtrace:\n");

    OE_TEST(size <= num_expected_symbols);
    {
        // Optimizations may cause certain frames to be omitted (due to inlining
        // or tail-call etc). We need to assert that the backtrace is an ordered
        // subset of expected backtrace.
        size_t num_skipped = 0;
        size_t idx = 0;

        // Iterate through the expected symbols
        for (size_t i = 0; i < num_expected_symbols; i++)
        {
            // GCC sometimes adds .constprop, .clone and other suffixes to
            // functions. Given func4, GCC could generate func4.constprop.0
            // that does a bit of the work done by func4, leaving the rest
            // for func4 to do. To handle the presence of such functions in
            // the backtrace, ignore suffixes in this comparision.
            if (strncmp(
                    expected_symbols[i],
                    symbols[idx],
                    strlen(expected_symbols[i])) == 0)
            {
                // Expected and actual symbols match.
                // Move past the current frame.
                oe_host_printf("%s(): (%p)\n", symbols[idx], buffer[idx]);
                ++idx;
            }
            else
            {
                // Mismatch. Mark this expected frame as skipped.
                // But do not move past the current frame.
                oe_host_printf(
                    "Skipped expected frame %s\n", expected_symbols[i]);
                ++num_skipped;
            }
        }

        oe_host_printf("\nSkipped %d frames\n", (int)num_skipped);

        // All the gathered frames must be consumed.
        OE_TEST(idx == size);

#ifndef NDEBUG
        // In debug mode, expected and actual backtraces must exactly match.
        // In release mode, some frames may be skipped.
        OE_TEST(num_skipped == 0);
#endif
    }

    oe_host_printf("\n");

    free(symbols);
}

extern "C" bool test(size_t num_syms, const char** syms)
{
    oe_host_printf("=== test()\n");

    Backtrace b;
    GetBacktrace(&b);

    OE_UNUSED(num_syms);
    OE_UNUSED(syms);

    OE_TEST(b.size > 0);

    char** _syms = backtrace_symbols(b.buffer, b.size);
    OE_TEST(_syms != NULL);

    _print_backtrace(b.buffer, (size_t)b.size, num_syms, syms);
    free(_syms);

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
        char** _syms = backtrace_symbols(b.buffer, b.size);
        OE_TEST(_syms != NULL);
        _print_backtrace(b.buffer, (size_t)b.size, num_syms, syms);

        free(_syms);
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
