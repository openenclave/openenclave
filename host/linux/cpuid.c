// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(__GNUC__)

#include "../host/cpuid.h"
#include <openenclave/bits/result.h>
#include <cpuid.h>

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
    unsigned int __maxlevel = __get_cpuid_max(__ext, 0);

    if (__maxlevel == 0 || __maxlevel < __leaf)
        return OE_UNSUPPORTED;

    if (__subleaf == NULL)
    {
        __cpuid(__leaf, *__eax, *__ebx, *__ecx, *__edx);
    }
    else
    {
        __cpuid_count(__leaf, *__subleaf, *__eax, *__ebx, *__ecx, *__edx);
    }
    return OE_OK;
}

#endif
