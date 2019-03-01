// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CPUIDCOUNT_H
#define _OE_CPUIDCOUNT_H

#if defined(__GNUC__)
#include <cpuid.h>
/* Same as __get_cpuid, but sub-leaf can be specified.
   Need this function as cpuid level 4 needs the sub-leaf to be specified in ECX
*/
static inline void oe_get_cpuid(
    unsigned int __leaf,
    unsigned int __subleaf,
    unsigned int* __eax,
    unsigned int* __ebx,
    unsigned int* __ecx,
    unsigned int* __edx)
{
    __cpuid_count(__leaf, __subleaf, *__eax, *__ebx, *__ecx, *__edx);
}
/* endif defined(__GNUC__) */
#elif defined(_MSC_VER)
#include <intrin.h>
#include <limits.h>
/* Same as __get_cpuid, but sub-leaf can be specified.
   Need this function as cpuid level 4 needs the sub-leaf to be specified in ECX
*/
static inline void oe_get_cpuid(
    unsigned int __leaf,
    unsigned int __subleaf,
    unsigned int* __eax,
    unsigned int* __ebx,
    unsigned int* __ecx,
    unsigned int* __edx)
{
    int registers[4] = {0};

    __cpuidex(registers, __leaf, __subleaf);

    *__eax = registers[0];
    *__ebx = registers[1];
    *__ecx = registers[2];
    *__edx = registers[3];
}
#endif /* defined(_MSC_VER) */

#endif /* _OE_CPUIDCOUNT_H */
