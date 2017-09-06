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
    oe_uint64_t rsp;
    oe_uint64_t rbp;
    oe_uint64_t rbx;
    oe_uint64_t r12;
    oe_uint64_t r13;
    oe_uint64_t r14;
    oe_uint64_t r15;
}
OE_Registers;

__attribute__((always_inline))
static __inline__ void OE_SaveRegisters(OE_Registers* regs)
{
    asm volatile(
        "mov %%rsp, %0\n\t"
        "mov %%rbp, %1\n\t"
        "mov %%rbx, %2\n\t"
        "mov %%r12, %3\n\t"
        "mov %%r13, %4\n\t"
        "mov %%r14, %5\n\t"
        "mov %%r15, %6\n\t"
        :
        "=m"(regs->rsp),
        "=m"(regs->rbp),
        "=m"(regs->rbx),
        "=m"(regs->r12),
        "=m"(regs->r13),
        "=m"(regs->r14),
        "=m"(regs->r15));
}

static __inline__ void OE_AssertRegisters(
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
