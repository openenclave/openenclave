#include <openenclave/bits/jump.h>

/*
 * Inline asm here requires to know the precise layout of the stack, so to
 * obtain rsp and RIP correctly. Thus this file must be compiled w/
 * optimization enabled.
 */

int OE_Setjmp(OE_Jmpbuf* env)
{
    asm volatile(
        /* Save RBX */
        "mov %%rbx, %0;"
        /* Save RBP */
        "mov %%rbp, %1;"
        /* Save R12 */
        "mov %%r12, %2;"
        /* Save R13 */
        "mov %%r13, %3;"
        /* Save R14 */
        "mov %%r14, %4;"
        /* Save R15 */
        "mov %%r15, %5;"
        /* Save stack pointer */
        "lea 8(%%rsp), %6;"
        /* Save instruction pointer */
        "mov (%%rsp), %7;"
        : "=m"(env->rbx),
          "=m"(env->rbp),
          "=m"(env->r12),
          "=m"(env->r13),
          "=m"(env->r14),
          "=m"(env->r15),
          "=r"(env->rsp),
          "=r"(env->rip)
        );

    return 0;
}

void OE_Longjmp(OE_Jmpbuf* env, int val)
{
    //size_t dummy;

    if (val == 0)
        val = 1;

    asm volatile(
        /* Restore RBX */
        "mov %1, %%rbx;"
        /* Restore RBP*/
        "mov %2, %%rbp;"
        /* Restore R12 */
        "mov %3, %%r12;"
        /* Restore R13 */
        "mov %4, %%r13;"
        /* Restore R14 */
        "mov %5, %%r14;"
        /* Restore R15 */
        "mov %6, %%r15;"
        /* Restore stack pointer */
        "mov %7, %%rsp;"
        /* Fetch and jump to instruction pointer */
        "jmp *%8;"
        :
        : "a"(val),
          "m" (env->rbx),
          "m" (env->rbp),
          "m"(env->r12),
          "m"(env->r13),
          "m"(env->r14),
          "m"(env->r15),
          "m"(env->rsp),
          "r"(env->rip)
        );
}

