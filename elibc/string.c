// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <limits.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <stdint.h>
#include <string.h>

size_t elibc_strlen(const char* s)
{
    return oe_strlen(s);
}

size_t elibc_strnlen(const char* s, size_t n)
{
    return oe_strnlen(s, n);
}

int elibc_strcmp(const char* s1, const char* s2)
{
    return oe_strcmp(s1, s2);
}

int elibc_strncmp(const char* s1, const char* s2, size_t n)
{
    return oe_strncmp(s1, s2, n);
}

int elibc_strcasecmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (toupper(*s1) == toupper(*s2)))
    {
        s1++;
        s2++;
    }

    return toupper(*s1) - toupper(*s2);
}

int elibc_strncasecmp(const char* s1, const char* s2, size_t n)
{
    while (n && *s1 && *s2 && toupper(*s1) == toupper(*s2))
    {
        n--;
        s1++;
        s2++;
    }

    if (n == 0)
        return 0;

    if (!*s1)
        return -1;

    if (!*s2)
        return 1;

    return toupper(*s1) - toupper(*s2);
}

char* elibc_strncpy(char* dest, const char* src, size_t n)
{
    char* p = dest;

    while (n-- && *src)
        *p++ = *src++;

    while (n--)
        *p++ = '\0';

    return dest;
}

char* elibc_strcpy(char* dest, const char* src)
{
    char* p = dest;

    while (*src)
        *p++ = *src++;

    *p = '\0';

    return dest;
}

char* elibc_strcat(char* dest, const char* src)
{
    char* p = dest + strlen(dest);

    while (*src)
        *p++ += *src++;

    *p = '\0';

    return dest;
}

char* elibc_strncat(char* dest, const char* src, size_t n)
{
    char* p = dest + strlen(dest);

    while (n-- && *src)
        *p++ = *src++;

    *p = '\0';

    return dest;
}

size_t elibc_strlcpy(char* dest, const char* src, size_t size)
{
    return oe_strlcpy(dest, src, size);
}

size_t elibc_strlcat(char* dest, const char* src, size_t size)
{
    return oe_strlcat(dest, src, size);
}

char* elibc_strchr(const char* s, int c)
{
    while (*s && *s != c)
        s++;

    if (*s == c)
        return (char*)s;

    return NULL;
}

char* elibc_index(const char* s, int c)
{
    return strchr(s, c);
}

char* elibc_strrchr(const char* s, int c)
{
    char* p = (char*)s + strlen(s);

    if (c == '\0')
        return p;

    while (p != s)
    {
        if (*--p == c)
            return p;
    }

    return NULL;
}

char* elibc_rindex(const char* s, int c)
{
    return strrchr(s, c);
}

char* elibc_strstr(const char* haystack, const char* needle)
{
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);

    if (nlen > hlen)
        return NULL;

    for (size_t i = 0; i < hlen - nlen + 1; i++)
    {
        if (memcmp(haystack + i, needle, nlen) == 0)
            return (char*)haystack + i;
    }

    return NULL;
}

void* elibc_memcpy(void* dest, const void* src, size_t n)
{
    return oe_memcpy(dest, src, n);
}

void* elibc_memset(void* s, int c, size_t n)
{
    return oe_memset(s, c, n);
}

int elibc_memcmp(const void* s1, const void* s2, size_t n)
{
    return oe_memcmp(s1, s2, n);
}

void* elibc_memmove(void* dest, const void* src, size_t n)
{
    return oe_memmove(dest, src, n);
}

char* elibc_strdup(const char* s)
{
    return strndup(s, ELIBC_SIZE_MAX);
}

char* elibc_strndup(const char* s, size_t n)
{
    char* p = NULL;

    if (s)
    {
        size_t len = strnlen(s, n);

        if (!(p = (char*)oe_malloc(len + 1)))
            return NULL;

        oe_memcpy(p, s, len);
        p[len] = '\0';
    }

    return p;
}
