// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/print.h>
#include "../args.h"

// Wrapper over the CPUID instruction.
void get_cpuid(
    unsigned int leaf,
    unsigned int subleaf,
    unsigned int* eax,
    unsigned int* ebx,
    unsigned int* ecx,
    unsigned int* edx)
{
    asm volatile("cpuid"
                 // CPU id instruction returns values in the following registers
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 // __leaf is passed in eax (0) and __subleaf in ecx (2)
                 : "0"(leaf), "2"(subleaf));
}

#define OE_GETSEC_OPCODE 0x370F
#define OE_GETSEC_CAPABILITIES 0x00

// Global to track state of TestSigillHandler execution.
// Making this volatile to prevent optimization by the compiler
// as g_handled_sigill is being used as a messaging mechanism
// during signal handling. This is modified in the signal
// handlers in the enclave and checked in the test functions.
static volatile enum {
    HANDLED_SIGILL_NONE,
    HANDLED_SIGILL_GETSEC,
    HANDLED_SIGILL_CPUID
} g_handled_sigill;

// 2nd-chance exception handler to continue on test triggered exceptions
uint64_t TestSigillHandler(oe_exception_record_t* exception)
{
    if (exception->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        switch (*((uint16_t*)exception->context->rip))
        {
            case OE_CPUID_OPCODE:
                exception->context->rip += 2;
                g_handled_sigill = HANDLED_SIGILL_CPUID;
                return OE_EXCEPTION_CONTINUE_EXECUTION;

            case OE_GETSEC_OPCODE:
                exception->context->rip += 2;
                g_handled_sigill = HANDLED_SIGILL_GETSEC;
                return OE_EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return OE_EXCEPTION_CONTINUE_SEARCH;
}

bool TestGetsecInstruction()
{
    // Arbitrary constants to verify r1/r2 have not been clobbered
    const uint32_t c_r1 = 0xDEADBEEF;
    const uint32_t c_r2 = 0xBEEFCAFE;

    uint32_t r1 = c_r1;
    uint32_t r2 = c_r2;

    g_handled_sigill = HANDLED_SIGILL_NONE;

    // Invoke GETSEC instruction (illegal in SGX) on CAPABILITIES leaf
    asm volatile("mov %0, %%rax\n\t" /* GETSEC */
                 "mov %1, %%rbx\n\t" /* reserved 1 */
                 "mov %2, %%rcx\n\t" /* reserved 2 */
                 "GETSEC\n\t"
                 :
                 : "i"(OE_GETSEC_CAPABILITIES), "m"(r1), "m"(r2)
                 : "rax", "rbx", "rcx");

    // Verify that unused variables are untouched on continue
    if (r1 != c_r1 || r2 != c_r2)
    {
        oe_host_printf(
            "TestGetsecInstruction stack parameters were corrupted.\n");
        return false;
    }
    else
    {
        oe_host_printf("TestGetsecInstruction stack parameters are ok.\n");
    }

    // Verify that illegal instruction was handled by test handler, not by
    // default
    if (g_handled_sigill != HANDLED_SIGILL_GETSEC)
    {
        oe_host_printf(
            "%d Illegal GETSEC did not raise 2nd chance exception.\n",
            g_handled_sigill);
        return false;
    }
    else
    {
        oe_host_printf("Success-Illegal GETSEC raised 2nd chance exception.\n");
        return true;
    }
}

// Test Intent: Solely tests unsupported cpuid leaf and if the 2nd chance
// exception handler in the enclave is executed.
// Procedure: The call to cpuid with the unsupported cpuid leaf  causes an
// illegal exception in the host and is passed to the enclave which invokes
// EmulateCpuid. This routine should return -1 for unsupported
// cpuid leaves and cause the 2nd chance exception handler to be invoked.
bool TestUnsupportedCpuidLeaf(uint32_t leaf)
{
    g_handled_sigill = HANDLED_SIGILL_NONE;
    uint32_t cpuid_rax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    get_cpuid(leaf, 0, &cpuid_rax, &ebx, &ecx, &edx);

    // Do something with the out param to prevent call from getting optimized
    // out
    if (cpuid_rax != 0)
    {
        oe_host_printf("The value of cpuidRAX is now: %d\n.", cpuid_rax);
    }

    if (g_handled_sigill != HANDLED_SIGILL_CPUID)
    {
        oe_host_printf(
            "Unsupported CPUID leaf %x did not raise 2nd chance exception.\n",
            leaf);
        return false;
    }
    else
    {
        oe_host_printf(
            "Success-Unsupported CPUID leaf %x raised 2nd chance exception.\n",
            leaf);
        return true;
    }
}

OE_ECALL void TestSigillHandling(void* args_)
{
    TestSigillHandlingArgs* args = (TestSigillHandlingArgs*)args_;
    oe_result_t result;

    args->ret = -1;

    if (!oe_is_outside_enclave(args, sizeof(TestSigillHandlingArgs)))
    {
        oe_host_printf("TestSigillHandlingArgs failed bounds check.\n");
        return;
    }

    // Register the sigill handler to catch test triggered exceptions
    result = oe_add_vectored_exception_handler(false, TestSigillHandler);
    if (result != OE_OK)
    {
        oe_host_printf("Failed to register TestSigillHandler.\n");
        return;
    }

    // Test illegal SGX instruction that is not emulated (GETSEC)
    if (!TestGetsecInstruction())
    {
        return;
    }

    // Test unsupported CPUID leaves
    if (!TestUnsupportedCpuidLeaf(OE_CPUID_LEAF_COUNT))
    {
        return;
    }

    if (!TestUnsupportedCpuidLeaf(OE_CPUID_EXTENDED_CPUID_LEAF))
    {
        return;
    }

    // Return enclave-cached CPUID leaves to host for further validation
    for (uint32_t i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
        if (oe_is_emulated_cpuid_leaf(i))
        {
            get_cpuid(
                i,
                0,
                &args->cpuid_table[i][OE_CPUID_RAX],
                &args->cpuid_table[i][OE_CPUID_RBX],
                &args->cpuid_table[i][OE_CPUID_RCX],
                &args->cpuid_table[i][OE_CPUID_RDX]);
        }
    }

    // Clean up sigill handler
    if (oe_remove_vectored_exception_handler(TestSigillHandler) != OE_OK)
    {
        oe_host_printf("Failed to unregister TestSigillHandler.\n");
        return;
    }

    oe_host_printf("TestSigillHandling: completed successfully.\n");
    args->ret = 0;

    return;
}
