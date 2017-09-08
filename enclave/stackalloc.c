#include <openenclave/enclave.h>
#include <openenclave/bits/utils.h>

void *OE_StackAlloc(size_t size, size_t alignment)
{
    if (!size)
        return OE_NULL;

    void* ptr = __builtin_alloca(size + alignment);

    if (alignment)
        ptr = (void*)OE_RoundUpToMultiple((uint64_t)ptr, alignment);

    return ptr;
}
