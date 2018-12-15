#include <openenclave/enclave.h>
#include <openenclave/bits/defs.h>

bool oe_is_within_enclave(const void* ptr, size_t sz)
{
    OE_UNUSED(ptr);
    OE_UNUSED(sz);
    return true;
}
