#include <setjmp.h>

int setjmp(jmp_buf env)
{
    __asm__ volatile(
	"/* @comment Setjmp inline asm */\n\t"
        /* Save RBX */
	"mov %%rbx, %0\n\t"
        /* Save RBP */
	"mov %%rbp, %1\n\t"
        /* Save R12 */
	"mov %%r12, %2\n\t"
        /* Save R13 */
	"mov %%r13, %3\n\t"
        /* Save R14 */
	"mov %%r14, %4\n\t"
        /* Save R15 */
	"mov %%r15, %5\n\t"
        /* Save stack pointer */
	"lea 8(%%rsp), %%rdx\n\t"
	"mov %%rdx, %6\n\t"
        /* Save instruction pointer */
	"mov (%%rsp), %%rdx\n\t"
	"mov %%rdx, %7\n\t"
        /* Clear RAX (return value) */
	"xor %%rax, %%rax\n\t"
        :
        "=m"(env->rbx),
        "=m"(env->rbp),
        "=m"(env->r12),
        "=m"(env->r13),
        "=m"(env->r14),
        "=m"(env->r15),
        "=m"(env->rsp),
        "=m"(env->rip));

    return 0;
}

void longjmp(jmp_buf env, int val)
{
    if (val == 0)
        val = 1;

    __asm__ volatile(
        /* Return value of corresponding Setjmp() */
	"mov %0, %%rax\n\t" 
        /* Restore RBX */
        "mov %1, %%rbx\n\t" 
        /* Restore RBP*/
        "mov %2, %%rbp\n\t" 
        /* Restore R12 */
        "mov %3, %%r12\n\t" 
        /* Restore R13 */
        "mov %4, %%r13\n\t" 
        /* Restore R14 */
        "mov %5, %%r14\n\t" 
        /* Restore R15 */
        "mov %6, %%r15\n\t" 
        /* Restore stack pointer */
        "mov %7, %%rdx\n\t" 
        "mov %%rdx, %%rsp\n\t"
        /* Fetch and jump to instruction pointer */
        "mov %8, %%rdx\n\t"
        "jmp *%%rdx\n\t"
        :
        :
        "m"(val),
        "m"(env->rbx),
        "m"(env->rbp),
        "m"(env->r12),
        "m"(env->r13),
        "m"(env->r14),
        "m"(env->r15),
        "m"(env->rsp),
        "m"(env->rip));
}
