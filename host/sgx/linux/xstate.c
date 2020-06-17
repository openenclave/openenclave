// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../xstate.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/trace.h>
#include "../cpuid.h"

#define XSAVE_SHIFT 26
#define OSXSAVE_SHIFT 27
#define AVX_SHIFT 28

// Returns if processor and OS support extended states feature.
// If cpuid.01h:ECX.XSAVE[bit 26] is 1, the processor supports the XSAVE/XRSTOR
// processor extended states feature, the XSETBV/XGETBV instructions, and XCR0
// If cpuid.01h:ECX.XSAVE[bit 27] is 1, it indicates that OS has set CR4,OSXSAVE
// to enable XSETBV/XGETBV instructions to access XCR0 and to support processor
// extended state management using XSAVE/XRSTOR.
static bool _is_xgetbv_supported()
{
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID Leaf 1
    oe_get_cpuid(1, 0, &eax, &ebx, &ecx, &edx);

    // Check if AVX instruction extensions (bit 28) are supported in the
    // processor
    if (!(ecx & (1 << AVX_SHIFT)))
        OE_TRACE_INFO("Processor does not support AVX instructions");
    else
        OE_TRACE_INFO("Processor supports AVX instructions");

    // Check bits 26 and 27 that indicate support for
    // XSAVE/XRSTOR/XSETBV/XGETBV/XCR0 and the OS has set these bits to allow
    // access.
    if (!(ecx & (1 << XSAVE_SHIFT)) || !(ecx & (1 << OSXSAVE_SHIFT)))
    {
        OE_TRACE_INFO("Plaform/OS does not support Extended Feature States");
        return false;
    }

    return true;
}

/* Returns the value of XCR0 register which is programmed by the OS */
uint64_t oe_get_xfrm()
{
    uint32_t eax, edx, index;
    eax = edx = 0;
    index = 0; // XCR0 register is returned

    // Ensure that Processor and OS support extended states feature. XGETBV will
    // #GP fault otherwise.
    if (_is_xgetbv_supported())
    {
        /* Invoke xgetbv to get the value of the Extended Control Register XCR0
         */
        asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
                     : "=a"(eax), "=d"(edx)
                     : "c"(index));
        return eax + ((uint64_t)edx << 32);
    }
    else
        return 0;
}