// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>

/*
**=====/=========================================================================
**
** oe_strlen()
** oe_strcmp()
** oe_strcpy()
** oe_strlcpy()
** oe_strlcat()
**
**==============================================================================
*/

size_t oe_strlen(const char* s)
{
    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    if (!p[0])
        return (size_t)(p - s);
    if (!p[1])
        return (size_t)(p - s + 1);
    if (!p[2])
        return (size_t)(p - s + 2);
    if (!p[3])
        return (size_t)(p - s + 3);
    if (!p[4])
        return (size_t)(p - s + 4);
    if (!p[5])
        return (size_t)(p - s + 5);

    /* Unreachable */
    return 0;
}

size_t oe_strnlen(const char* s, size_t n)
{
    const char* p = s;

    while (n-- && *p)
        p++;

    return (size_t)(p - s);
}

int oe_strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

int oe_strncmp(const char* s1, const char* s2, size_t n)
{
    /* Compare first n characters only */
    while (n && (*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
        n--;
    }

    /* If first n characters matched */
    if (n == 0)
        return 0;

    /* Return difference of mismatching characters */
    return *s1 - *s2;
}

size_t oe_strlcpy(char* dest, const char* src, size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return (size_t)(src - start);
}

size_t oe_strlcat(char* dest, const char* src, size_t size)
{
    size_t n = 0;

    if (size)
    {
        char* end = dest + size - 1;

        while (*dest && dest != end)
        {
            dest++;
            n++;
        }

        while (*src && dest != end)
        {
            n++;
            *dest++ = *src++;
        }

        *dest = '\0';
    }

    while (*src)
    {
        src++;
        n++;
    }

    return n;
}

/*
**==============================================================================
**
** oe_memset()
** oe_memcpy()
** oe_memcmp()
**
**==============================================================================
*/

static inline void _oe_memcpy(void* dest, const void* src, size_t n)
{
// TODO: Revisit this later. Looks like compilers might replace
// __builtin_X with the C library version of X.
#if defined(__x86_64__) || defined(_M_X64)
    __builtin_memcpy(dest, src, n);
#else
    unsigned char* d = (unsigned char*)dest;
    unsigned char* s = (unsigned char*)src;
    while (n--)
        *d++ = *s++;
#endif
}
void* oe_memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

    while (n >= 1024)
    {
        _oe_memcpy(p, q, 1024);
        n -= 1024;
        p += 1024;
        q += 1024;
    }

    while (n >= 256)
    {
        _oe_memcpy(p, q, 256);
        n -= 256;
        p += 256;
        q += 256;
    }

    while (n >= 64)
    {
        _oe_memcpy(p, q, 64);
        n -= 64;
        p += 64;
        q += 64;
    }

    while (n >= 16)
    {
        _oe_memcpy(p, q, 16);
        n -= 16;
        p += 16;
        q += 16;
    }

    while (n--)
        *p++ = *q++;

    return dest;
}

static inline void _oe_memset(void* s, int c, size_t n)
{
// TODO: Revisit this later. Looks like compilers might replace
// __builtin_X with the C library version of X.
#if defined(__x86_64__) || defined(_M_X64)
    __builtin_memset(s, c, n);
#else
    unsigned char* s_ = (unsigned char*)s;
    while (n--)
        *s_++ = (unsigned char)c;
#endif
}

void* oe_memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

    while (n >= 1024)
    {
        _oe_memset(p, c, 1024);
        n -= 1024;
        p += 1024;
    }

    while (n >= 256)
    {
        _oe_memset(p, c, 256);
        n -= 256;
        p += 256;
    }

    while (n >= 64)
    {
        _oe_memset(p, c, 64);
        n -= 64;
        p += 64;
    }

    while (n >= 16)
    {
        _oe_memset(p, c, 16);
        n -= 16;
        p += 16;
    }

    while (n--)
        *p++ = (unsigned char)c;

    return s;
}

int oe_memcmp(const void* s1, const void* s2, size_t n)
{
    const unsigned char* p = (const unsigned char*)s1;
    const unsigned char* q = (const unsigned char*)s2;

    while (n--)
    {
        int r = *p++ - *q++;

        if (r)
            return r;
    }

    return 0;
}

void* oe_memmove(void* dest, const void* src, size_t n)
{
    char* p = (char*)dest;
    const char* q = (const char*)src;

    if (p != q && n > 0)
    {
        if (p <= q)
        {
            oe_memcpy(p, q, n);
        }
        else
        {
            for (q += n, p += n; n--; p--, q--)
                p[-1] = q[-1];
        }
    }

    return p;
}
