#include <openenclave/internal/enclavelibc.h>

int oe_sched_yield(void)
{
    __asm__ __volatile__("pause");
    return 0;
}
