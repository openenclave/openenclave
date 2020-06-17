// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/ctype.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/safecrt.h>

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

char* oe_strstr(const char* haystack, const char* needle)
{
    size_t hlen = oe_strlen(haystack);
    size_t nlen = oe_strlen(needle);

    if (nlen > hlen)
        return NULL;

    for (size_t i = 0; i < hlen - nlen + 1; i++)
    {
        if (memcmp(haystack + i, needle, nlen) == 0)
            return (char*)haystack + i;
    }

    return NULL;
}

char* oe_strdup(const char* s)
{
    char* p;
    size_t n;

    if (!s)
        return NULL;

    n = oe_strlen(s) + 1;

    if (!(p = oe_malloc(n)))
        return NULL;

    if (oe_memcpy_s(p, n, s, n) != OE_OK)
        return NULL;

    return p;
}

char* oe_strchr(const char* s, int c)
{
    while (*s && *s != c)
        s++;

    if (*s == c)
        return (char*)s;

    return NULL;
}

char* oe_strrchr(const char* s, int c)
{
    char* p = (char*)s + oe_strlen(s);

    if (c == '\0')
        return p;

    while (p != s)
    {
        if (*--p == c)
            return p;
    }

    return NULL;
}

char* oe_strchrnul(const char* s, int c)
{
    char* p;

    if (!(p = oe_strchr(s, c)))
        p = (char*)(s + oe_strlen(s));

    return p;
}

size_t oe_strspn(const char* s, const char* accept)
{
    const char* p = s;

    while (*p)
    {
        if (!oe_strchr(accept, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

size_t oe_strcspn(const char* s, const char* reject)
{
    const char* p = s;

    while (*p)
    {
        if (oe_strchr(reject, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}
