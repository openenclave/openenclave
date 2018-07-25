// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/defs.h>
#include <openenclave/internal/jump.h>

OE_CHECK_SIZE(sizeof(oe_jmpbuf_t), 64);

/*
 * This file must be compiled with optimization enabled because the code
 * relies on the precise layout of the stack (and thereby preamble) to obtain
 * the correct rsp and rip.
 *
 * Really, this should go into a separate .s-file to ensure correct register
 * access.
 */

int oe_setjmp(oe_jmpbuf_t* env)
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
          "=r"(env->rip));

    return 0;
}

void oe_longjmp(oe_jmpbuf_t* env, int val)
{
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
          "m"(env->rbx),
          "m"(env->rbp),
          "m"(env->r12),
          "m"(env->r13),
          "m"(env->r14),
          "m"(env->r15),
          "m"(env->rsp),
          "d"(env->rip));
}
