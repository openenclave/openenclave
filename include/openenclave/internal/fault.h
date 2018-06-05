// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_FAULT_H
#define _OE_FAULT_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

OE_INLINE void OE_IllegalInstruction(void)
{
    __asm__ volatile("ud2\n\t");
}

OE_INLINE void OE_SegmentationViolation(void)
{
    *((int*)0) = 0;
}

OE_INLINE void OE_Pause(void)
{
    __asm__ volatile("pause\n\t");
}

OE_INLINE void OE_DivideByZero(void)
{
    __asm__ volatile(
        "mov $0, %eax\n\t"
        "div %eax, %eax\n\t");
}

OE_EXTERNC_END

#endif /* _OE_FAULT_H */
