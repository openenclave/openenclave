#include <openenclave/bits/atomic.h>
#include "refs.h"

#ifndef NDEBUG

static volatile uint64_t _refs;

uint64_t OE_RefsGet()
{
    return _refs;
}

void OE_RefsIncrement()
{
    OE_AtomicIncrement(&_refs);
}

void OE_RefsDecrement()
{
    OE_AtomicDecrement(&_refs);
}

#endif
