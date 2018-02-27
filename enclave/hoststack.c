#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include "td.h"

void* OE_HostAllocForCallHost(size_t size, size_t alignment, bool isZeroInit)
{
    TD* td = TD_Get();

    /* Fail if size is zero or no thread data object */
    if (size == 0 || !td)
    {
        OE_Abort();
        return NULL;
    }

    /* Fail if host stack pointer is not aligned on a word boundary */
    if (OE_RoundUpToMultiple(td->host_rsp, sizeof(uint64_t)) != td->host_rsp)
    {
        OE_Abort();
        return NULL;
    }

    /* Round size request to a multiple of the word size */
    size = OE_RoundUpToMultiple(size, sizeof(uint64_t));

    /* Set minimum alignment */
    if (alignment == 0)
        alignment = sizeof(uint64_t);

    /* Fail if alignment is not a multiple of the word size */
    if (OE_RoundUpToMultiple(alignment, sizeof(uint64_t)) != alignment)
    {
        OE_Abort();
        return NULL;
    }

    size_t total_size = size + alignment;

    td->host_rsp -= total_size;

    void* ptr = (void*)td->host_rsp;

    /* Align the memory */
    ptr = (void*)OE_AlignPointer(ptr, alignment);

    /* Clear the memory if requested */
    if (ptr && isZeroInit)
        OE_Memset(ptr, 0, size);

    return ptr;
}
