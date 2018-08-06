#ifndef _OE_DLMALLOC_SCHED_H
#define _OE_DLMALLOC_SCHED_H

static __inline__ int sched_yield(void)
{
    __asm__ __volatile__("pause");
    return 0;
}

#endif /* _OE_DLMALLOC_SCHED_H */
