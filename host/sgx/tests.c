// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/sgx/tests.h>
#include "../hostthread.h"
#include "cpuid.h"
#include "sgxquoteprovider.h"

static bool _has_quote_provider = false;

static void _check_quote_provider(void)
{
    _has_quote_provider = (oe_initialize_quote_provider() == OE_OK);
}

bool oe_sgx_has_quote_provider(void)
{
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, _check_quote_provider);
    return _has_quote_provider;
}

bool oe_sgx_is_flc_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID
    oe_get_cpuid(
        CPUID_EXTENDED_FEATURE_FLAGS_LEAF, 0x0, &eax, &ebx, &ecx, &edx);

    // Check if FLC is supported by the processor
    return ecx & CPUID_EXTENDED_FEATURE_FLAGS_SGX_FLC_MASK;
}
