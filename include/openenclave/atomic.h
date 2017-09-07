#ifndef _OE_ATOMIC_H
#define _OE_ATOMIC_H

#include "defs.h"

OE_INLINE uint64_t OE_AtomicRead(volatile uint64_t* x)
{
    return __sync_add_and_fetch(x, 0);
}

OE_INLINE uint64_t OE_AtomicIncrement(volatile uint64_t* x)
{
    return __sync_add_and_fetch(x, 1);
}

OE_INLINE uint64_t OE_AtomicDecrement(volatile uint64_t* x)
{
    return __sync_sub_and_fetch(x, 1);
}

#endif /* _OE_ATOMIC_H */
