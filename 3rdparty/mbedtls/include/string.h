#ifndef _OE_MBEDTLS_STRING_H
#define _OE_MBEDTLS_STRING_H

#include "bits/alltypes.h"
#include "bits/mbedtls_libc.h"

static __inline 
size_t strlen(const char* s)
{
    return __mbedtls_libc.strlen(s);
}

static __inline 
int strcmp(const char* s1, const char* s2)
{
    return __mbedtls_libc.strcmp(s1, s2);
}

static __inline 
int strncmp(const char* s1, const char* s2, size_t n)
{
    return __mbedtls_libc.strncmp(s1, s2, n);
}

static __inline
char* strncpy(char* dest, const char* src, size_t n)
{
    return __mbedtls_libc.strncpy(dest, src, n);
}

static __inline 
char* strstr(const char* haystack, const char* needle)
{
    return __mbedtls_libc.strstr(haystack, needle);
}

static __inline 
void* memset(void* s, int c, size_t n)
{
    return __mbedtls_libc.memset(s, c, n);
}

static __inline 
void* memcpy(void* dest, const void* src, size_t n)
{
    return __mbedtls_libc.memcpy(dest, src, n);
}

static __inline 
int memcmp(const void* s1, const void* s2, size_t n)
{
    return __mbedtls_libc.memcmp(s1, s2, n);
}

static __inline 
void* memmove(void* dest, const void* src, size_t n)
{
    return __mbedtls_libc.memmove(dest, src, n);
}

static __inline 
int rand(void)
{
    return __mbedtls_libc.rand();
}

#endif /* _OE_MBEDTLS_STRING_H */
