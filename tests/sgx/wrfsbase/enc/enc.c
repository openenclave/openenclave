// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/tests.h>
#include "wrfsbase_t.h"

static void* fs_before_exception;

static void _cpuid(
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

// This function will generate the divide by zero function.
// The handler will catch this exception and fix it, and continue execute.
// It will return 0 if success.
static int _divide_by_zero_exception_function(void)
{
    // Making ret, f and d volatile to prevent optimization
    volatile int ret = 1;
    volatile float f = 0;
    volatile double d = 0;

    f = 0.31f;
    d = 0.32;

    // Using inline assembly for idiv to prevent it being optimized out
    // completely. Specify edi as the used register to ensure that 32-bit
    // division is done. 64-bit division generates a 3 byte instruction rather
    // than 2 bytes.
    register int edi __asm__("edi") = 0;
    asm volatile("idiv %1"
                 : "=a"(ret)
                 : "r"(edi) // Divisor of 0 is hard-coded
                 : "%1",
                   "cc"); // cc indicates that flags will be clobbered by ASM

    // Check if the float registers are recovered correctly after the exception
    // is handled.
    if (f < 0.309 || f > 0.321 || d < 0.319 || d > 0.321)
    {
        return -1;
    }

    return 0;
}

static uint64_t _divide_by_zero_handler(oe_exception_record_t* exception_record)
{
    void* current_fs;

    asm volatile("mov %%fs:0, %0" : "=r"(current_fs));

    if (current_fs != fs_before_exception)
        return OE_EXCEPTION_ABORT_EXECUTION;

    if (exception_record->code != OE_EXCEPTION_DIVIDE_BY_ZERO)
        return OE_EXCEPTION_ABORT_EXECUTION;

    // Skip the idiv instruction - 2 is tied to the size of the idiv instruction
    // and can change with a different compiler/build. Minimizing this with the
    // use of the inline assembly for integer division
    exception_record->context->rip += 2;
    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

void enc_wrfsbase(int simulation_mode, int negative_test)
{
    static uint64_t temp_td[256];
    void* original_fs_after_exception;
    void* original_fs_after_cpuid;
    void* original_fs;
    void* new_fs_after_exception;
    void* new_fs_after_cpuid;
    void* new_fs;
    void* recovered_fs;

    OE_UNUSED(fs_before_exception);
    OE_UNUSED(original_fs_after_cpuid);
    OE_UNUSED(original_fs_after_exception);
    OE_UNUSED(new_fs_after_cpuid);
    OE_UNUSED(new_fs_after_exception);

    OE_TEST(
        oe_add_vectored_exception_handler(true, _divide_by_zero_handler) ==
        OE_OK);

    temp_td[0] = (uint64_t)temp_td;

    asm volatile("mov %%fs:0, %0" : "=r"(original_fs));

    /* Only test with exceptions in non-simulation mode */
    if (!simulation_mode)
    {
        fs_before_exception = original_fs;

        /* Expect FS is persisted after an exception */
        OE_TEST(_divide_by_zero_exception_function() == 0);

        asm volatile("mov %%fs:0, %0" : "=r"(original_fs_after_exception));

        /* Expect FS is persisted after CPUID emulation */
        {
            uint32_t cpuid_rax = 0;
            uint32_t ebx = 0;
            uint32_t ecx = 0;
            uint32_t edx = 0;

            _cpuid(0, 0, &cpuid_rax, &ebx, &ecx, &edx);
        }

        asm volatile("mov %%fs:0, %0" : "=r"(original_fs_after_cpuid));
    }

    /* change FS */
    asm volatile("wrfsbase %0 " : : "a"(temp_td));
    asm volatile("mov %%fs:0, %0" : "=r"(new_fs));

    /* Only test with exceptions in non-simulation mode */
    if (!simulation_mode)
    {
        fs_before_exception = new_fs;

        /* Expect FS is persisted after an exception */
        OE_TEST(_divide_by_zero_exception_function() == 0);

        asm volatile("mov %%fs:0, %0" : "=r"(new_fs_after_exception));

        /* Expect FS is persisted after CPUID emulation */
        {
            uint32_t cpuid_rax = 0;
            uint32_t ebx = 0;
            uint32_t ecx = 0;
            uint32_t edx = 0;

            _cpuid(0, 0, &cpuid_rax, &ebx, &ecx, &edx);
        }

        asm volatile("mov %%fs:0, %0" : "=r"(new_fs_after_cpuid));
    }

    if (negative_test)
    {
        /* Calling OCALLs will fail if FS is changed */
        host_dummy();
    }

    /* restore FS */
    asm volatile("wrfsbase %0 " : : "a"(original_fs));
    asm volatile("mov %%fs:0, %0" : "=r"(recovered_fs));

    if (!simulation_mode)
    {
        OE_TEST(original_fs_after_exception == original_fs);
        OE_TEST(original_fs_after_cpuid == original_fs);
        OE_TEST(new_fs_after_exception == new_fs);
        OE_TEST(new_fs_after_cpuid == new_fs);
    }
    OE_TEST(new_fs == temp_td);
    OE_TEST(recovered_fs == original_fs);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
