#ifndef _OE_JUMP_H
#define _OE_JUMP_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

typedef struct _OE_Jmpbuf
{
    oe_uint64_t rsp;
    oe_uint64_t rbp;
    oe_uint64_t rip;
    oe_uint64_t rbx;
    oe_uint64_t r12;
    oe_uint64_t r13;
    oe_uint64_t r14;
    oe_uint64_t r15;
}
OE_Jmpbuf;

OE_CHECK_SIZE(sizeof(OE_Jmpbuf), 64);

int OE_Setjmp(OE_Jmpbuf* env);

void OE_Longjmp(OE_Jmpbuf* env, int val);

OE_EXTERNC_END

#endif /* _OE_ALLOC_H */
