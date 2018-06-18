#ifndef _OE_MBEDTLS_MBEDTLS_LIBC_H
#define _OE_MBEDTLS_MBEDTLS_LIBC_H

#include "alltypes.h"

typedef struct _mbedtls_libc
{
    size_t (*strlen)(const char* s);
    int (*strcmp)(const char* s1, const char* s2);
    int (*strncmp)(const char* s1, const char* s2, size_t n);
    char* (*strncpy)(char* dest, const char* src, size_t n);
    char* (*strstr)(const char* haystack, const char* needle);
    void* (*memset)(void* s, int c, size_t n);
    void* (*memcpy)(void* dest, const void* src, size_t n);
    int (*memcmp)(const void* s1, const void* s2, size_t n);
    void* (*memmove)(void* dest, const void* src, size_t n);
    void* (*malloc)(size_t size);
    void (*free)(void* ptr);
    void* (*calloc)(size_t nmemb, size_t size);
    void* (*realloc)(void* ptr, size_t size);
    int (*vsnprintf)(char* str, size_t size, const char* format, va_list ap);
    int (*vprintf)(const char* format, va_list ap);
    int (*rand)(void);
#if 0
    time_t (*time)(time_t* tloc);
    struct tm* (*gmtime)(const time_t* timep);
#endif
}
mbedtls_libc_t;

extern mbedtls_libc_t __mbedtls_libc;

#endif /* _OE_MBEDTLS_MBEDTLS_LIBC_H */
