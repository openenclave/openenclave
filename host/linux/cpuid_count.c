// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(__GNUC__)

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
    unsigned int __ext = __leaf & 0x80000000;
    unsigned int __maxlevel = __get_cpuid_max(__ext, 0);

    if (__maxlevel == 0 || __maxlevel < __leaf)
        return 0;

    __cpuid_count(__leaf, __subleaf, *__eax, *__ebx, *__ecx, *__edx);
    return 1;
}

#endif