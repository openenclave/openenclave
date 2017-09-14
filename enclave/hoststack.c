#include <openenclave/enclave.h>
#include <openenclave/bits/utils.h>
#include "td.h"

void *OE_HostStackMemalign(
    size_t size, 
    size_t alignment)
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

#if 0
    OE_Memset(ptr, 0xAA, total_size);
#endif

    /* Align the memory */
    ptr = (void*)OE_AlignPointer(ptr, alignment);

    return ptr;
}

void *OE_HostStackMalloc(size_t size)
{
    return OE_HostStackMemalign(size, sizeof(uint64_t));
}

void *OE_HostStackCalloc(size_t nmem, size_t size)
{
    void* ptr = OE_HostStackMalloc(nmem * size);
    
    if (ptr)
        OE_Memset(ptr, 0, nmem * size);

    return ptr;
}

char* OE_HostStackStrdup(const char* s)
{
    size_t n = OE_Strlen(s);

    char* r = (char*)OE_HostStackMalloc(n + 1);

    if (r)
        OE_Memcpy(r, s, n + 1);

    return r;
}
