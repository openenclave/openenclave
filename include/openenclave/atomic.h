#ifndef _OE_ATOMIC_H
#define _OE_ATOMIC_H

#include "defs.h"

OE_INLINE oe_uint64_t OE_AtomicRead(volatile oe_uint64_t* x)
{
    return __sync_add_and_fetch(x, 0);
}

OE_INLINE oe_uint64_t OE_AtomicIncrement(volatile oe_uint64_t* x)
{
    return __sync_add_and_fetch(x, 1);
}

OE_INLINE oe_uint64_t OE_AtomicDecrement(volatile oe_uint64_t* x)
{
    return __sync_sub_and_fetch(x, 1);
}

#endif /* _OE_ATOMIC_H */
