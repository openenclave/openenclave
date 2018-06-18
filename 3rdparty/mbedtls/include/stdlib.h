#ifndef _OE_MBEDTLS_STDLIB_H
#define _OE_MBEDTLS_STDLIB_H

#include "bits/alltypes.h"
#include "bits/mbedtls_libc.h"

static __inline
void* malloc(size_t size)
{
    return __mbedtls_libc.malloc(size);
}

static __inline
void free(void* ptr)
{
    return __mbedtls_libc.free(ptr);
}

static __inline
void* calloc(size_t nmemb, size_t size)
{
    return __mbedtls_libc.calloc(nmemb, size);
}

static __inline
void* realloc(void* ptr, size_t size)
{
    return __mbedtls_libc.realloc(ptr, size);
}

#endif /* _OE_MBEDTLS_STDLIB_H */
