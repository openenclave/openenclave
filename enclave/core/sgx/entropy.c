// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/entropy.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rdrand.h>
#include <openenclave/internal/rdseed.h>
#include "cpuid.h"

typedef uint64_t (*_entropy_function_t)(void);

OE_INLINE bool _has_cpuid_feature(
    uint32_t leaf,
    uint32_t feature,
    uint32_t feature_register)
{
    oe_assert(feature_register < OE_CPUID_REG_COUNT);
    uint64_t r[OE_CPUID_REG_COUNT] = {0};
    r[OE_CPUID_RAX] = leaf;
    return (
        (oe_emulate_cpuid(
             &r[OE_CPUID_RAX],
             &r[OE_CPUID_RBX],
             &r[OE_CPUID_RCX],
             &r[OE_CPUID_RDX]) == 0) &&
        (r[feature_register] & feature));
}

static oe_entropy_kind_t _get_entropy_kind()
{
    oe_entropy_kind_t result = OE_ENTROPY_KIND_NONE;

    /* The ordering of checks is important: we want the presence of
     * stronger entropy sources to supersede the weaker ones, so
     * go from least to most preferred sources.
     */
    if (_has_cpuid_feature(1, OE_CPUID_RDRAND_FEATURE, OE_CPUID_RCX))
        result = OE_ENTROPY_KIND_RDRAND;

    if (_has_cpuid_feature(7, OE_CPUID_RDSEED_FEATURE, OE_CPUID_RBX))
        result = OE_ENTROPY_KIND_RDSEED;

    return result;
}

oe_result_t oe_get_entropy(void* output, size_t len, oe_entropy_kind_t* kind)
{
    oe_result_t result = OE_UNEXPECTED;
    _entropy_function_t get_entropy = NULL;
    unsigned char* p = (unsigned char*)output;
    size_t bytes_left = len;

    if (kind)
        *kind = OE_ENTROPY_KIND_NONE;

    if (output)
        memset(output, 0, len);

    if (!output || !kind)
        OE_RAISE(OE_INVALID_PARAMETER);

    *kind = _get_entropy_kind();
    if (*kind == OE_ENTROPY_KIND_RDSEED)
        get_entropy = oe_rdseed;
    else if (*kind == OE_ENTROPY_KIND_RDRAND)
        get_entropy = oe_rdrand;
    else
        OE_RAISE(OE_UNSUPPORTED);

    while (bytes_left > 0)
    {
        uint64_t random = get_entropy();
        size_t copy_size =
            (sizeof(random) > bytes_left) ? bytes_left : sizeof(random);
        memcpy(p, &random, copy_size);
        p += copy_size;
        bytes_left -= copy_size;
    }

    result = OE_OK;

done:
    return result;
}
