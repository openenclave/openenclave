// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
#include "VectorException_t.h"

#include "exception_handler_stack.h"

// Defined in sigill_handling.c
extern "C" void get_cpuid(
    unsigned int leaf,
    unsigned int subleaf,
    unsigned int* eax,
    unsigned int* ebx,
    unsigned int* ecx,
    unsigned int* edx);

static int done[2];
static unsigned int c[2];
static int hits1[2];
static int hits2[2];

#define AESNI_INSTRUCTIONS 0x02000000u

int test_cpuid_instruction(unsigned int what, int use_exception_handler_stack)
{
    int index = (use_exception_handler_stack) ? 1 : 0;
    if (!done[index])
    {
        unsigned int a, b, d;
        get_cpuid(1, 0, &a, &b, &c[index], &d);
        // Do something with out param so call to cpuid is not optimized out.
        if (a == 0)
        {
            oe_host_printf("This is the value of a: %d", a);
        }

        // This should be executed only once.
        ++hits1[index];
        done[index] = 1;
    }

    // This should be executed 3 times.
    ++hits2[index];
    return ((c[index] & what) != 0) ? 1 : 0;
}

__attribute__((constructor)) void test_cpuid_constructor()
{
    test_cpuid_instruction(500, 0);
    test_cpuid_instruction(600, 0);
    test_cpuid_instruction(AESNI_INSTRUCTIONS, 0);

    void* stack = malloc(EXCEPTION_HANDLER_STACK_SIZE);
    if (!stack)
        return;

    oe_sgx_td_t* td = oe_sgx_get_td();

    oe_sgx_td_set_exception_handler_stack(
        td, stack, EXCEPTION_HANDLER_STACK_SIZE);

    test_cpuid_instruction(500, 1);
    test_cpuid_instruction(600, 1);
    test_cpuid_instruction(AESNI_INSTRUCTIONS, 1);

    oe_sgx_td_set_exception_handler_stack(td, NULL, 0);

    free(stack);
}

void enc_test_cpuid_in_global_constructors()
{
    OE_TEST(done[0] == 1);
    OE_TEST(c[0] != 0);
    OE_TEST(hits1[0] == 1);
    OE_TEST(hits2[0] == 3);

    OE_TEST(done[1] == 1);
    OE_TEST(c[1] != 0);
    OE_TEST(hits1[1] == 1);
    OE_TEST(hits2[1] == 3);
    oe_host_printf(
        "enc_test_cpuid_in_global_constructors: completed successfully.\n");
}
