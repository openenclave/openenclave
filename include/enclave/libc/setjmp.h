#ifndef __ELIBC_SETJMP_H
#define __ELIBC_SETJMP_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

struct __jmp_buf
{
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
};

typedef struct __jmp_buf jmp_buf[1];

int setjmp(jmp_buf env);

void longjmp(jmp_buf env, int val);

__ELIBC_END

#endif /* __ELIBC_SETJMP_H */
