#include <openenclave/bits/atomic.h>
#include "crypto.h"

static volatile uint64_t _cryptoRefs;

uint64_t OE_CryptoRefsGet()
{
    return _cryptoRefs;
}

void OE_CryptoRefsIncrement()
{
    OE_AtomicIncrement(&_cryptoRefs);
}

void OE_CryptoRefsDecrement()
{
    OE_AtomicDecrement(&_cryptoRefs);
}
