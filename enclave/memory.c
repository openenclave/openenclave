#include <openenclave.h>
#include <__openenclave/globals.h>

bool OE_IsWithinEnclave(
    const void* p,
    size_t n)
{
    const uint8_t* start = (const uint8_t*)p;
    const uint8_t* end = (const uint8_t*)p + n;
    const uint8_t* base = (const uint8_t*)__OE_GetEnclaveBase();
    uint64_t size = __OE_GetEnclaveSize();

    if (!(start >= base && start < (base + size)))
        return false;

    if (n)
    {
        end--;

        if (!(end >= base && end < (base + size)))
            return false;
    }

    return true;
}

bool OE_IsOutsideEnclave(
    const void* p,
    size_t n)
{
    return !OE_IsWithinEnclave(p, n);
}
