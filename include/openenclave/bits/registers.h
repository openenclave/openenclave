#ifndef _OE_ASM_H
#define _OE_ASM_H

#include <stdlib.h>
#include <string.h>
#include <openenclave/defs.h>
#include <openenclave/types.h>

#define __oe_nop asm volatile("nop\n\t")
#define __oe_ud2 asm volatile("ud2\n\t")

OE_EXTERNC_BEGIN

typedef struct _OE_Registers
{
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
}
OE_Registers;

OE_INLINE void OE_AssertRegisters(
    const OE_Registers* lhs,
    const OE_Registers* rhs)
{
    if (lhs->rsp != rhs->rsp)
        abort();

    if (lhs->rbp != rhs->rbp)
        abort();

    if (lhs->rbx != rhs->rbx)
        abort();

    if (lhs->r12 != rhs->r12)
        abort();

    if (lhs->r13 != rhs->r13)
        abort();

    if (lhs->r14 != rhs->r14)
        abort();

    if (lhs->r15 != rhs->r15)
        abort();
}

int OE_SetGSRegisterBase(const void *ptr);

int OE_GetGSRegisterBase(const void **ptr);

OE_EXTERNC_END

#endif /* _OE_ASM_H */
