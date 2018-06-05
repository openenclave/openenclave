// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cpuid.h>
#include "../args.h"

#include "../../../host/linux/cpuid_count.c"

#define OE_GETSEC_OPCODE 0x370F
#define OE_GETSEC_CAPABILITIES 0x00

// Global to track state of TestSigillHandler execution.
// Making this volatile to prevent optimization by the compiler
// as g_handledSigill is being used as a messaging mechanism
// during signal handling. This is modified in the signal
// handlers in the enclave and checked in the test functions.
static volatile enum {
    HANDLED_SIGILL_NONE,
    HANDLED_SIGILL_GETSEC,
    HANDLED_SIGILL_CPUID
} g_handledSigill;

// 2nd-chance exception handler to continue on test triggered exceptions
uint64_t TestSigillHandler(OE_ExceptionRecord* exception)
{
    if (exception->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        switch (*((uint16_t*)exception->context->rip))
        {
            case OE_CPUID_OPCODE:
                exception->context->rip += 2;
                g_handledSigill = HANDLED_SIGILL_CPUID;
                return OE_EXCEPTION_CONTINUE_EXECUTION;

            case OE_GETSEC_OPCODE:
                exception->context->rip += 2;
                g_handledSigill = HANDLED_SIGILL_GETSEC;
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

    g_handledSigill = HANDLED_SIGILL_NONE;

    // Invoke GETSEC instruction (illegal in SGX) on CAPABILITIES leaf
    asm volatile(
        "mov %0, %%rax\n\t" /* GETSEC */
        "mov %1, %%rbx\n\t" /* reserved 1 */
        "mov %2, %%rcx\n\t" /* reserved 2 */
        "GETSEC\n\t"
        :
        : "i"(OE_GETSEC_CAPABILITIES), "m"(r1), "m"(r2)
        : "rax", "rbx", "rcx");

    // Verify that unused variables are untouched on continue
    if (r1 != c_r1 || r2 != c_r2)
    {
        OE_HostPrintf(
            "TestGetsecInstruction stack parameters were corrupted.\n");
        return false;
    }
    else
    {
        OE_HostPrintf("TestGetsecInstruction stack parameters are ok.\n");
    }

    // Verify that illegal instruction was handled by test handler, not by
    // default
    if (g_handledSigill != HANDLED_SIGILL_GETSEC)
    {
        OE_HostPrintf(
            "%d Illegal GETSEC did not raise 2nd chance exception.\n",
            g_handledSigill);
        return false;
    }
    else
    {
        OE_HostPrintf("Success-Illegal GETSEC raised 2nd chance exception.\n");
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
    g_handledSigill = HANDLED_SIGILL_NONE;
    uint32_t cpuidRAX;

    // Invoking cpuid in assembly and making it volatile to prevent cpuid from
    // being optimized out
    asm volatile(
        "cpuid"
        : "=a"(cpuidRAX) // Return value in cpuidRAX
        : "0"(leaf)
        : "ebx", "ecx", "edx", "cc", "memory");

    if (g_handledSigill != HANDLED_SIGILL_CPUID)
    {
        OE_HostPrintf(
            "Unsupported CPUID leaf %x did not raise 2nd chance exception.\n",
            leaf);
        return false;
    }
    else
    {
        OE_HostPrintf(
            "Success-Unsupported CPUID leaf %x raised 2nd chance exception.\n",
            leaf);
        return true;
    }
}

OE_ECALL void TestSigillHandling(void* args_)
{
    TestSigillHandlingArgs* args = (TestSigillHandlingArgs*)args_;
    args->ret = -1;

    if (!OE_IsOutsideEnclave(args, sizeof(TestSigillHandlingArgs)))
    {
        OE_HostPrintf("TestSigillHandlingArgs failed bounds check.\n");
        return;
    }

    // Register the sigill handler to catch test triggered exceptions
    void* handler = OE_AddVectoredExceptionHandler(false, TestSigillHandler);
    if (handler == NULL)
    {
        OE_HostPrintf("Failed to register TestSigillHandler.\n");
        return;
    }

    // Test illegal SGX instruction that is not emulated (GETSEC)
    if (!TestGetsecInstruction(args))
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
    for (int i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
        int supported = __get_cpuid_count(
            i,
            0,
            &args->cpuidTable[i][OE_CPUID_RAX],
            &args->cpuidTable[i][OE_CPUID_RBX],
            &args->cpuidTable[i][OE_CPUID_RCX],
            &args->cpuidTable[i][OE_CPUID_RDX]);

        if (!supported)
        {
            OE_HostPrintf("Unsupported CPUID leaf %d requested.\n", i);
            return;
        }
    }

    // Clean up sigill handler
    if (OE_RemoveVectoredExceptionHandler(handler) != 0)
    {
        OE_HostPrintf("Failed to unregister TestSigillHandler.\n");
        return;
    }

    OE_HostPrintf("TestSigillHandling: completed successfully.\n");
    args->ret = 0;

    return;
}
