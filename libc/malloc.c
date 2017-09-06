#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <openenclave/enclave.h>

void *malloc(size_t size)
{
    return OE_Malloc(size);
}

void free(void *ptr)
{
    OE_Free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    return OE_Calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
    return OE_Realloc(ptr, size);
}

void *memalign(size_t alignment, size_t size)
{
    return OE_Memalign(alignment, size);
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    extern int dlposix_memalign(void **memptr, size_t alignment, size_t size);
    return dlposix_memalign(memptr, alignment, size);
}
