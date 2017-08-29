#include <stdlib.h>
#include <stdint.h>

static uint64_t _seed;

int rand(void)
{
    unsigned long r;

    __asm__ volatile("rdrand %%rax\n\t"
        "mov %%rax, %0\n\t"
        :
        "=m"(r));

    r *= _seed + 1;

    return ((r >> 32) ^ (r & 0x00000000FFFFFFFF));
}

void srand(unsigned int seed)
{
    _seed = (uint64_t)seed;
}
