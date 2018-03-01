#ifndef _OE_JUMP_H
#define _OE_JUMP_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

typedef struct _OE_Jmpbuf
{
    /* These are the registers that are preserved across function calls
     * according to the 'System V AMD64 ABI' calling conventions:
     * RBX, RSP, RBP, R12, R13, R14, R15. In addition, OE_Setjmp() saves
     * the RIP register (intruction pointer) to know where to jump back to).
     */
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
} OE_Jmpbuf;

OE_CHECK_SIZE(sizeof(OE_Jmpbuf), 64);

int OE_Setjmp(OE_Jmpbuf* env);

void OE_Longjmp(OE_Jmpbuf* env, int val);

OE_EXTERNC_END

#endif /* _OE_ALLOC_H */
