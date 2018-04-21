// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CPUID_H
#define _OE_CPUID_H
#include <openenclave/types.h>
#define OE_CPUID_OPCODE 0xA20F

#define OE_CPUID_LEAF_COUNT 8

#define OE_CPUID_RAX 0
#define OE_CPUID_RBX 1
#define OE_CPUID_RCX 2
#define OE_CPUID_RDX 3
#define OE_CPUID_REG_COUNT 4

#if defined(__linux)
#include <cpuid.h>
/* Same as __get_cpuid, but sub-leaf can be specified.
   Need this function as cpuid level 4 needs the sub-leaf to be specified in ECX
*/
static __inline int __get_cpuid_count(
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

#endif /* _OE_CPUID_H */
