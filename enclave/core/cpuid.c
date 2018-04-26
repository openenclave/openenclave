// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "cpuid.h"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/cpuid.h>
#include <openenclave/bits/enclavelibc.h>

static uint32_t _OE_CpuidTable[OE_CPUID_LEAF_COUNT][OE_CPUID_REG_COUNT];

/*
**==============================================================================
**
** OE_InitializeCpuid()
**
**     Initialize the enclave view of CPUID information as provided by host
**     during _InitializeEnclave call as part of OE_CreateEnclave.
**
**==============================================================================
*/
void OE_InitializeCpuid(uint64_t argIn)
{
    OE_InitEnclaveArgs* args = (OE_InitEnclaveArgs*)argIn;
    if (args != NULL)
    {
        OE_Memcpy(
            _OE_CpuidTable,
            args->cpuidTable,
            OE_CPUID_LEAF_COUNT * OE_CPUID_REG_COUNT *
                sizeof(_OE_CpuidTable[0][0]));
    }
}

/*
**==============================================================================
**
** OE_EmulateCpuid()
**
**     Emulate the result of a CPUID call from within the enclave by returning
**     results initialized by the host during enclave creation.
**
**     This approach allows enclave app code a consistent view of untrusted
**     CPUID results compared to a per callout approach, but limits the extent
**     of emulation to only the cached CPUID leaves, which currently only
**     includes up to structured extended information. Specifically for leaf 4,
**     only subleaf 0 i.e. topology of processor cores in a physical pacakage
**     is cached. Deterministic Cache Parameters for all levels of the
**     processor cache are not supported.
**
**     This primarily allows checking of CPU feature bits important for compat
*      and crypto.
**
**     Returns 0 if referenced CPUID leaf (and subleaf) is available, -1
*      otherwise.
**     For CPUID leaf 4, subleaf of 0 is only available as noted above.
**==============================================================================
*/
int OE_EmulateCpuid(uint64_t* rax, uint64_t* rbx, uint64_t* rcx, uint64_t* rdx)
{
    // upper bits zeroed on 64-bit for CPUID
    uint32_t cpuidLeaf = (*rax) & 0xFFFFFFFF;
    uint32_t cpuidSubLeaf = (*rcx) & 0xFFFFFFFF;

    if (cpuidLeaf < OE_CPUID_LEAF_COUNT)
    {
        // For leaf 4 of cpuid, only subleaf of 0 is emulated
        if ((cpuidLeaf == 4) && (cpuidSubLeaf != 0))
            return -1;

        *rax = _OE_CpuidTable[cpuidLeaf][OE_CPUID_RAX];
        *rbx = _OE_CpuidTable[cpuidLeaf][OE_CPUID_RBX];
        *rcx = _OE_CpuidTable[cpuidLeaf][OE_CPUID_RCX];
        *rdx = _OE_CpuidTable[cpuidLeaf][OE_CPUID_RDX];
        return 0;
    }
    return -1;
}

#include "../../common/cpuid.c"
