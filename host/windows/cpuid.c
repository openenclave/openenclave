// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#if defined(_MSC_VER)

#include "../host/cpuid.h"
#include <openenclave/bits/result.h>
#include <intrin.h>
#include <limits.h>

/* Same as __get_cpuid, but sub-leaf can be specified.
   Need this function as cpuid level 4 needs the sub-leaf to be specified in ECX
*/
oe_result_t oe_get_cpuid(
    unsigned int __leaf,
    unsigned int* __subleaf,
    unsigned int* __eax,
    unsigned int* __ebx,
    unsigned int* __ecx,
    unsigned int* __edx)
{
    unsigned int __ext = __leaf & 0x80000000;
    int max_registers[] = {0, 0, 0, 0};
    __cpuid(max_registers, __ext);

    if (max_registers[0] == 0 || max_registers[0] < __leaf)
        return OE_UNSUPPORTED;

    // Ensure casting to int will be as expected.
    if (*__eax > INT_MAX
        || *__ebx > INT_MAX
        || *__ecx > INT_MAX
        || *__edx > INT_MAX)
        return OE_UNSUPPORTED;

    int registers[] = {*__eax, *__ebx, *__ecx, *__edx};
    if (__subleaf == NULL)
    {
        __cpuid(registers, __leaf);
    }
    else
    {
        __cpuidex(registers, __leaf, *__subleaf);
    }

    return OE_OK;
}

#endif
