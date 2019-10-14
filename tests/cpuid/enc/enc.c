// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "cpuid_t.h"

static void _execute_cpuid_instruction(
    unsigned int leaf,
    unsigned int subleaf,
    unsigned int* eax,
    unsigned int* ebx,
    unsigned int* ecx,
    unsigned int* edx)
{
    asm volatile("cpuid"
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 : "0"(leaf), "2"(subleaf));
}

static uint64_t _exception_handler(oe_exception_record_t* exception)
{
    if (exception->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        if (*((uint16_t*)exception->context->rip) == OE_CPUID_OPCODE)
        {
            /* Perform CPUID emulation later in the continuation hook. */
            return OE_EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return OE_EXCEPTION_CONTINUE_SEARCH;
}

extern void (*oe_continue_execution_hook)(oe_exception_record_t* record);

static void _continue_execution_hook(oe_exception_record_t* record)
{
    oe_context_t* context = record->context;

    if (*((uint16_t*)context->rip) == OE_CPUID_OPCODE)
    {
        uint32_t rax;
        uint32_t rbx;
        uint32_t rcx;
        uint32_t rdx;

        oe_host_printf("=== _continue_execution_hook()\n");

        if (context->rax == 0xff)
        {
            rax = 0xaa;
            rbx = 0xbb;
            rcx = 0xcc;
            rdx = 0xdd;
        }
        else
        {
            /* Call into host to execute the CPUID instruction. */
            cpuid_ocall(
                (uint32_t)context->rax, /* leaf */
                (uint32_t)context->rcx, /* subleaf */
                &rax,
                &rbx,
                &rcx,
                &rdx);
        }

        context->rax = rax;
        context->rbx = rbx;
        context->rcx = rcx;
        context->rdx = rdx;

        /* Skip over the CPUID instrunction. */
        context->rip += 2;
    }
}

void test_cpuid(void)
{
    oe_result_t result;

    /* Install an exception handler. */
    result = oe_add_vectored_exception_handler(false, _exception_handler);
    OE_TEST(result == OE_OK);

    /* Install the exception continuation hook. */
    oe_continue_execution_hook = _continue_execution_hook;

    /* Execute the CPUID instruction. */
    {
        const uint32_t leaf = 4;
        const uint32_t subleaf = 1; /* unsupported by default in OE. */
        uint32_t eax = 0;
        uint32_t ebx = 0;
        uint32_t ecx = 0;
        uint32_t edx = 0;

        /* Perform the CPUID instruction. */
        _execute_cpuid_instruction(leaf, subleaf, &eax, &ebx, &ecx, &edx);

        oe_host_printf("=== _execute_cpuid_instruction()\n");
        oe_host_printf("eax=%x\n", eax);
        oe_host_printf("ebx=%x\n", ebx);
        oe_host_printf("ecx=%x\n", ecx);
        oe_host_printf("edx=%x\n", edx);
    }

    /* Execute the CPUID instruction with 0xff leaf. */
    {
        const uint32_t leaf = 0xff;
        const uint32_t subleaf = 0;
        uint32_t eax = 0;
        uint32_t ebx = 0;
        uint32_t ecx = 0;
        uint32_t edx = 0;

        /* Perform the CPUID instruction. */
        _execute_cpuid_instruction(leaf, subleaf, &eax, &ebx, &ecx, &edx);

        OE_TEST(eax == 0xaa);
        OE_TEST(ebx == 0xbb);
        OE_TEST(ecx == 0xcc);
        OE_TEST(edx == 0xdd);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
