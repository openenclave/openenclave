#include <stdlib.h>

/*
 * Random implementation needed by libcxx as alternative to device oriented
 * randomness (/dev/rand)
 */

unsigned int arc4random(void)
{
    unsigned long r;
    __asm__ volatile("rdrand %%rax\n\t"
                     "mov %%rax, %0\n\t"
                     : "=m"(r));
    return (unsigned int)r;
}
