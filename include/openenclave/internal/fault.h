// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_FAULT_H
#define _OE_FAULT_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

OE_INLINE void oe_illegal_instruction(void)
{
    __asm__ volatile("ud2\n\t");
}

OE_INLINE void oe_segmentation_violation(void)
{
    *((volatile int*)0) = 0;
}

OE_INLINE void oe_pause(void)
{
    __asm__ volatile("pause\n\t");
}

OE_INLINE void oe_divide_by_zero(void)
{
    __asm__ volatile("mov $0, %eax\n\t"
                     "div %eax, %eax\n\t");
}

OE_EXTERNC_END

#endif /* _OE_FAULT_H */
