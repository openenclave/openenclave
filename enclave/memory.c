#include <openenclave.h>
#include <oeinternal/globals.h>

oe_bool OE_IsWithinEnclave(
    const void* p,
    oe_size_t n)
{
    const oe_uint8_t* start = (const oe_uint8_t*)p;
    const oe_uint8_t* end = (const oe_uint8_t*)p + n;
    const oe_uint8_t* base = (const oe_uint8_t*)__OE_GetEnclaveBase();
    oe_uint64_t size = __OE_GetEnclaveSize();

    if (!(start >= base && start < (base + size)))
        return oe_false;

    if (n)
    {
        end--;

        if (!(end >= base && end < (base + size)))
            return oe_false;
    }

    return oe_true;
}

oe_bool OE_IsOutsideEnclave(
    const void* p,
    oe_size_t n)
{
    return !OE_IsWithinEnclave(p, n);
}
