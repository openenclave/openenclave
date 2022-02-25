// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "cpuid.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include "platform_t.h"

static uint32_t _cpuid_table[OE_CPUID_LEAF_COUNT][OE_CPUID_REG_COUNT];

/*
**==============================================================================
**
** oe_initialize_cpuid()
**
**     Initialize the enclave view of CPUID information as provided by host
**     during _initialize_enclave call as part of oe_create_enclave.
**
**==============================================================================
*/
oe_result_t oe_initialize_cpuid(void)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t retval;

    OE_CHECK(oe_sgx_get_cpuid_table_ocall(
        &retval, _cpuid_table, sizeof(_cpuid_table)));

    OE_CHECK((oe_result_t)retval);

    // Abort the enclave if AESNI support is not present in the cached
    // CPUID Feature information (cpuid leaf of 1)
    if (!(_cpuid_table[1][OE_CPUID_RCX] & OE_CPUID_AESNI_FEATURE))
        oe_abort();

    // set max input value for basic and extended
    _cpuid_table[oe_get_emulated_cpuid_leaf_index(0)][OE_CPUID_RAX] =
        OE_CPUID_MAX_BASIC;
    _cpuid_table[oe_get_emulated_cpuid_leaf_index(0x80000000)][OE_CPUID_RAX] =
        OE_CPUID_MAX_EXTENDED;

    result = OE_OK;

done:

    if (result != OE_OK)
    {
        oe_memset_s(
            _cpuid_table, sizeof(_cpuid_table), 0, sizeof(_cpuid_table));
    }

    return result;
}

/*
**==============================================================================
**
** oe_emulate_cpuid()
**
**     Emulate the result of a CPUID call from within the enclave by returning
**     results initialized by the host during enclave creation.
**
**     This approach allows enclave app code a consistent view of untrusted
**     CPUID results compared to a per callout approach, but limits the extent
**     of emulation to only the cached CPUID leaves, which currently only
**     includes up to structured extended information. Specifically for leaf 4,
**     only subleaf 0 i.e. topology of processor cores in a physical package
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
int oe_emulate_cpuid(uint64_t* rax, uint64_t* rbx, uint64_t* rcx, uint64_t* rdx)
{
    // upper bits zeroed on 64-bit for CPUID
    uint32_t cpuid_leaf = (*rax) & 0xFFFFFFFF;
    uint32_t cpuid_sub_leaf = (*rcx) & 0xFFFFFFFF;

    // emulate the cpuid leaves and find the corresponding index
    uint32_t index = oe_get_emulated_cpuid_leaf_index(cpuid_leaf);
    if (index == OE_UINT32_MAX)
        return -1;

    // For leaf 4 of cpuid, only subleaf of 0 is emulated
    if ((cpuid_leaf == 4) && (cpuid_sub_leaf != 0))
        return -1;

    *rax = _cpuid_table[index][OE_CPUID_RAX];
    *rbx = _cpuid_table[index][OE_CPUID_RBX];
    *rcx = _cpuid_table[index][OE_CPUID_RCX];
    *rdx = _cpuid_table[index][OE_CPUID_RDX];
    return 0;
}
