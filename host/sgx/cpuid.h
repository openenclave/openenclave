// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CPUIDCOUNT_H
#define _OE_CPUIDCOUNT_H

#if defined(__GNUC__)
#include <cpuid.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#include <limits.h>
#else
#error "oe_get_cpuid(): no cpuid intrinsic mapping for this compiler"
#endif

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
#if defined(__GNUC__)
    __cpuid_count(__leaf, __subleaf, *__eax, *__ebx, *__ecx, *__edx);
#elif defined(_MSC_VER)
    int registers[4] = {0};

    __cpuidex(registers, __leaf, __subleaf);

    *__eax = registers[0];
    *__ebx = registers[1];
    *__ecx = registers[2];
    *__edx = registers[3];
#endif
}
#endif /* _OE_CPUIDCOUNT_H */
