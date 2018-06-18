// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "openenclave/internal/cpuid.h"
#include <cpuid.h>

oe_result_t oe_get_cpuid(
    unsigned int __leaf,
    unsigned int __subleaf,
    unsigned int* __eax,
    unsigned int* __ebx,
    unsigned int* __ecx,
    unsigned int* __edx)
{
    oe_result_t result = OE_UNEXPECTED;
    int supported = 0;

    supported = __get_cpuid_count(__leaf, __subleaf, *__eax, *__ebx, *__ecx, *__edx);
    if (!supported)
    {
        result = OE_UNSUPPORTED;
        return result;
    }
    result = OE_OK;
    return result;
}