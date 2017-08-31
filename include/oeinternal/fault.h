#ifndef _OE_FAULT_H
#define _OE_FAULT_H

#include "../oecommon/defs.h"

OE_EXTERNC_BEGIN

OE_INLINE void OE_IllegalInstruction(void)
{
    asm volatile("ud2\n\t");
}

OE_INLINE void OE_SegmentationViolation(void)
{
    *((int*)0) = 0;
}

OE_INLINE void OE_Pause(void)
{
    asm volatile("pause\n\t");
}

OE_INLINE void OE_DivideByZero(void)
{
    asm volatile(
        "mov $0, %eax\n\t"
        "div %eax, %eax\n\t");
}

OE_EXTERNC_END

#endif /* _OE_ALLOC_H */
