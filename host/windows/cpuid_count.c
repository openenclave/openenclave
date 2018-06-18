// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#if defined(_MSC_VER)

#include "../cpuid_count.h"
#include <cpuid.h>

/* Same as __get_cpuid, but sub-leaf can be specified.
   Need this function as cpuid level 4 needs the sub-leaf to be specified in ECX
*/
int __get_cpuid_count(
    unsigned int __leaf,
    unsigned int __subleaf,
    unsigned int* __eax,
    unsigned int* __ebx,
    unsigned int* __ecx,
    unsigned int* __edx)
{
    unsigned int __maxlevel, __max_eax, __max_ebx, __max_ecx, __max_edx;
    cpuid(0, __max_eax, __max_ebx, __max_ecx, __max_edx);

    if (__max_eax == 0 || __max_eax < __leaf)
        return 0;

    int registers[] = {*__eax, *__ebx, *__ecx, *__edx};
    __cpuidex(registers, __leaf, __subleaf);

    return 1;
}

#endif