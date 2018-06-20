// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>

size_t oe_strlen(const char* s)
{
    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    if (!p[0])
        return p - s;
    if (!p[1])
        return p - s + 1;
    if (!p[2])
        return p - s + 2;
    if (!p[3])
        return p - s + 3;
    if (!p[4])
        return p - s + 4;
    if (!p[5])
        return p - s + 5;

    /* Unreachable */
    return 0;
}

size_t oe_strnlen(const char* s, size_t n)
{
    const char* p = s;

    while (n-- && *p)
        p++;

    return p - s;
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

char* oe_strncpy(char* dest, const char* src, size_t n)
{
    char* p = dest;

    while (n-- && *src)
        *p++ = *src++;

    while (n--)
        *p++ = '\0';

    return dest;
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

    return src - start;
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

char* oe_strstr(const char* haystack, const char* needle)
{
    size_t hlen = oe_strlen(haystack);
    size_t nlen = oe_strlen(needle);

    if (nlen > hlen)
        return NULL;

    for (size_t i = 0; i < hlen - nlen + 1; i++)
    {
        if (oe_memcmp(haystack + i, needle, nlen) == 0)
            return (char*)haystack + i;
    }

    return NULL;
}

static void* _memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;
}

void* oe_memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

#if defined(__GNUC__)

    while (n >= 1024)
    {
        __builtin_memcpy(p, q, 1024);
        n -= 1024;
        p += 1024;
        q += 1024;
    }

    while (n >= 256)
    {
        __builtin_memcpy(p, q, 256);
        n -= 256;
        p += 256;
        q += 256;
    }

    while (n >= 64)
    {
        __builtin_memcpy(p, q, 64);
        n -= 64;
        p += 64;
        q += 64;
    }

    while (n >= 16)
    {
        __builtin_memcpy(p, q, 16);
        n -= 16;
        p += 16;
        q += 16;
    }

#endif

    _memcpy(p, q, n);

    return dest;
}

static void* _memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = c;

    return s;
}

void* oe_memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

#if defined(__GNUC__)

    while (n >= 1024)
    {
        __builtin_memset(p, c, 1024);
        n -= 1024;
        p += 1024;
    }

    while (n >= 256)
    {
        __builtin_memset(p, c, 256);
        n -= 256;
        p += 256;
    }

    while (n >= 64)
    {
        __builtin_memset(p, c, 64);
        n -= 64;
        p += 64;
    }

    while (n >= 16)
    {
        __builtin_memset(p, c, 16);
        n -= 16;
        p += 16;
    }

#endif

    _memset(p, c, n);

    return s;
}

static int _memcmp(const void* s1, const void* s2, size_t n)
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

int oe_memcmp(const void* s1, const void* s2, size_t n)
{
    return _memcmp(s1, s2, n);
}

static void* _memmove(void* dest, const void* src, size_t n)
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

void* oe_memmove(void* dest, const void* src, size_t n)
{
    return _memmove(dest, src, n);
}

// The optimizer may generate calls to memcmp, memset, memcpy, and memmove.
// Provide weak forms here in case these cannot be found elsewhere.
OE_WEAK_ALIAS(_memcmp, memcmp);
OE_WEAK_ALIAS(_memset, memset);
OE_WEAK_ALIAS(_memcpy, memcpy);
OE_WEAK_ALIAS(_memmove, memmove);
