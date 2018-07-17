// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#if defined(_MSC_VER)

#include "../host/cpuid.h"
#include <intrin.h>
#include <limits.h>

/* Same as __get_cpuid, but sub-leaf can be specified.
   Need this function as cpuid level 4 needs the sub-leaf to be specified in ECX
*/
void oe_get_cpuid(
    unsigned int __leaf,
    unsigned int __subleaf,
    unsigned int* __eax,
    unsigned int* __ebx,
    unsigned int* __ecx,
    unsigned int* __edx)
{
    int registers[] = {*__eax, *__ebx, *__ecx, *__edx};
    __cpuidex(registers, __leaf, __subleaf);
}

#endif
