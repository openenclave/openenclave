// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// The line numbers in this file are referenced by the gdb
// test script commands.gdb. If you edit this file, update the
// test script as well.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "oe_gdb_test_t.h"

bool g_square_called = false;

int enc_add(int a, int b)
{
    // c is marked volatile to prevent compiler optimizations.
    // c is changed by the debugger.
    volatile int c = a + b;
    OE_TEST(c == 11);
    printf("hello: c = %d\n", c);

    // Expect debugger to change c to 100
    OE_TEST(c == 100);
    printf("hello: c = %d\n", c);

    // Expect debugger to call square and change c.
    OE_TEST(c == 10000);
    OE_TEST(g_square_called);
    printf("hello: c = %d\n", c);
    return c;
}

static void _raise_exceptions(void)
{
    // Raise CPUID. This is handled by oecore.
    unsigned int c;
    asm("movl  $1, %%eax   \n\t"
        "cpuid             \n\t"
        : "=c"(c)
        :
        : "eax", "ebx", "edx");

    // Raise rdtsc. This is handled via a handler below.
    register uint64_t rax __asm__("rax");
    register uint64_t rdx __asm__("rdx");
    asm volatile("rdtsc" : "=r"(rax), "=r"(rdx));
}

// The following function is intended to be called by the debugger.
// It must be retained via OE_EXPORT.
OE_EXPORT
int square(int x)
{
    printf("square called with %d\n", x);
    printf(
        "x lies %s\n",
        oe_is_within_enclave(&x, sizeof(x)) ? "within enclave"
                                            : "outside enclave");
    g_square_called = true;

    // Raising signal in a function called by gdb crashes gdb 8.0 and above.
    // _raise_exceptions();
    return x * x;
}

static void enclave_function(void)
{
    volatile uint64_t enc_magic = 0;
    OE_TEST(host_function() == OE_OK);
    // The following assertion will fail if the debugger was not able to walk
    // the ocall stack back to the enclave and set the value of enc_magic.
    OE_TEST(enc_magic == MAGIC_VALUE);
    _raise_exceptions();
}

void enc_test_stack_stitching(void)
{
    _raise_exceptions();
    enclave_function();
}

#define RDTSC_OPCODE 0x310f
// 2nd-chance exception handler to continue on test triggered exceptions
static uint64_t _rdtsc_sigill_handler(oe_exception_record_t* exception)
{
    if (exception->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        if (*((uint16_t*)exception->context->rip) == RDTSC_OPCODE)
        {
            exception->context->rip += 2;
            return OE_EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return OE_EXCEPTION_CONTINUE_SEARCH;
}

__attribute__((constructor)) void enc_constructor(void)
{
    oe_add_vectored_exception_handler(false, _rdtsc_sigill_handler);
    _raise_exceptions();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
