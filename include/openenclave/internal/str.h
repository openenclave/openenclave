// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_STR_H
#define _OE_STR_H

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mem.h"

#define STR_NPOS ((size_t)-1)

#define STR_NULL_INIT \
    {                 \
        MEM_NULL_INIT \
    }

OE_STATIC_ASSERT(sizeof(size_t) == sizeof(char*));

MEM_INLINE size_t __str_min(size_t x, size_t y)
{
    return x < y ? x : y;
}

MEM_INLINE size_t __str_max(size_t x, size_t y)
{
    return x > y ? x : y;
}

typedef struct _str_t
{
    mem_t __mem;
} str_t;

MEM_INLINE char* __str_ptr(const str_t* str)
{
    return (char*)str->__mem.__ptr;
}

MEM_INLINE size_t __str_len(const str_t* str)
{
    return str->__mem.__size - 1;
}

MEM_INLINE size_t __str_size(const str_t* str)
{
    return str->__mem.__size;
}

MEM_INLINE int str_ok(const str_t* str)
{
    return str && str->__mem.__magic == MEM_MAGIC;
}

MEM_INLINE const char* str_ptr(const str_t* str)
{
    return (const char*)mem_ptr((const mem_t*)str);
}

MEM_INLINE char* str_mutable_ptr(str_t* str)
{
    return (char*)mem_mutable_ptr((mem_t*)str);
}

MEM_INLINE int str_dynamic(str_t* str, char* ptr, size_t cap)
{
    if (mem_dynamic((mem_t*)str, ptr, 0, cap) != 0)
        return -1;

    return mem_catc((mem_t*)str, '\0');
}

MEM_INLINE int str_static(str_t* str, char* ptr, size_t cap)
{
    if (mem_static((mem_t*)str, ptr, cap) != 0)
        return -1;

    return mem_catc((mem_t*)str, '\0');
}

MEM_INLINE size_t str_len(const str_t* str)
{
    return mem_size((const mem_t*)str) - 1;
}

MEM_INLINE size_t str_size(const str_t* str)
{
    return mem_size((const mem_t*)str);
}

MEM_INLINE size_t str_cap(const str_t* str)
{
    return mem_cap((const mem_t*)str);
}

MEM_INLINE int str_reserve(str_t* str, size_t cap)
{
    return mem_reserve((mem_t*)str, cap);
}

MEM_INLINE int str_clear(str_t* str)
{
    if (mem_clear((mem_t*)str) != 0)
        return -1;

    return mem_catc((mem_t*)str, '\0');
}

MEM_INLINE int str_free(str_t* str)
{
    return mem_free((mem_t*)str);
}

MEM_INLINE int str_cpy(str_t* str, const char* s)
{
    if (!s)
        return -1;

    return mem_cpy((mem_t*)str, s, strlen(s) + 1);
}

MEM_INLINE int str_ncpy(str_t* str, const char* s, size_t len)
{
    if (!s)
        return -1;

    if (mem_cpy((mem_t*)str, s, __str_min(strlen(s), len)) != 0)
        return -1;

    return mem_catc((mem_t*)str, '\0');
}

MEM_INLINE int str_cat(str_t* str, const char* s)
{
    if (!s)
        return -1;

    return mem_insert((mem_t*)str, str_len(str), s, strlen(s));
}

MEM_INLINE int str_ncat(str_t* str, const char* s, size_t len)
{
    if (!s)
        return -1;

    len = __str_min(strlen(s), len);
    return mem_insert((mem_t*)str, str_len(str), s, len);
}

MEM_INLINE int str_catc(str_t* str, const char c)
{
    if (!c)
        return -1;

    return mem_insert((mem_t*)str, str_len(str), &c, 1);
}

MEM_INLINE int str_insert(str_t* str, size_t pos, const char* s)
{
    if (!str_ok(str) || !s)
        return -1;

    if (pos > str_len(str))
        return -1;

    return mem_insert((mem_t*)str, pos, s, strlen(s));
}

MEM_INLINE int str_remove(str_t* str, size_t pos, size_t len)
{
    size_t slen;

    if (!str_ok(str))
        return -1;

    slen = str_len(str);

    if (pos > slen)
        return -1;

    if (pos + len > slen)
        len = slen - pos;

    return mem_remove((mem_t*)str, pos, len);
}

MEM_INLINE int str_substr(str_t* str, const char* s, size_t pos, size_t len)
{
    size_t slen;

    if (!str_ok(str) || !s)
        return -1;

    slen = strlen(s);

    if (pos > slen)
        return -1;

    if (pos + len > slen)
        len = slen - pos;

    return str_ncpy(str, s + pos, len);
}

MEM_INLINE int str_replace(
    str_t* str,
    const char* match,
    size_t mlen,
    const char* replacement,
    size_t rlen)
{
    size_t pos;

    if (!str_ok(str) || !match || !replacement)
        return -1;

    if (mlen == 0)
        return -1;

    for (pos = 0; pos < __str_len(str);)
    {
        if (strncmp(__str_ptr(str) + pos, match, mlen) == 0)
        {
            if (rlen > mlen)
            {
                size_t delta = rlen - mlen;

                if (str_reserve(str, __str_size(str) + delta) != 0)
                    return -1;

                memmove(
                    __str_ptr(str) + pos + rlen,
                    __str_ptr(str) + pos + mlen,
                    __str_size(str) - pos - mlen);

                memcpy(__str_ptr(str) + pos, replacement, rlen);

                str->__mem.__size += delta;
            }
            else
            {
                size_t delta = mlen - rlen;

                memmove(
                    __str_ptr(str) + pos + rlen,
                    __str_ptr(str) + pos + mlen,
                    __str_size(str) - pos - rlen);

                memcpy(__str_ptr(str) + pos, replacement, rlen);

                str->__mem.__size -= delta;
            }

            pos += rlen;
        }
        else
        {
            pos++;
        }
    }

    return 0;
}

MEM_PRINTF_FORMAT(2, 3)
MEM_INLINE int str_printf(str_t* str, const char* format, ...)
{
    int r;

    if (!str_ok(str))
        return -1;

    str_clear(str);

    va_list ap;
    va_start(ap, format);
    r = vsnprintf(str_mutable_ptr(str), str_cap(str), format, ap);

    if (r < 0)
        return -1;

    va_end(ap);

    /* If buffer was not big enough and using dynamic memory */
    if (r + 1 > str_cap(str))
    {
        /* Expand memory allocation to required size */
        if (str_reserve(str, (size_t)r + 1) != 0)
            return -1;

        /* Retry the operation */
        va_list ap;
        va_start(ap, format);
        r = vsnprintf(str_mutable_ptr(str), str_cap(str), format, ap);

        if (r < 0)
            return -1;

        va_end(ap);
    }

    /* Set the size */
    str->__mem.__size = (size_t)r + 1;

    return 0;
}

MEM_INLINE int str_fgets(str_t* str, FILE* stream)
{
    int c;
    size_t i;

    if (!str_ok(str) || !stream)
        return -1;

    if (feof(stream))
        return 1;

    str_clear(str);

    for (i = 0; (c = fgetc(stream)) != EOF; i++)
    {
        if (str_reserve(str, i + 1) != 0)
            return -1;

        __str_ptr(str)[__str_len(str)] = (char)c;
        __str_ptr(str)[str->__mem.__size++] = '\0';

        if (c == '\n')
            break;
    }

    /* End of file */
    if (__str_len(str) == 0)
        return 1;

    return 0;
}

MEM_INLINE int str_ltrim(str_t* str, const char* delim)
{
    const char* start;
    const char* p;

    if (!str_ok(str) || !delim)
        return -1;

    start = __str_ptr(str);
    p = start;

    while (strchr(delim, *p))
        p++;

    if (p != start)
        return str_remove(str, 0, (size_t)(p - start));

    return 0;
}

MEM_INLINE int str_rtrim(str_t* str, const char* delim)
{
    const char* start;
    const char* end;
    const char* p;

    if (!str_ok(str) || !delim)
        return -1;

    start = __str_ptr(str);
    end = start + __str_len(str);
    p = end;

    while (p != start && strchr(delim, p[-1]))
        p--;

    if (p != end)
        return str_remove(str, (size_t)(p - start), (size_t)(end - p));

    return 0;
}

MEM_INLINE int str_split(str_t* str, const char* delim, str_t* lhs, str_t* rhs)
{
    const char* start;
    const char* end;
    const char* p;
    int found = 0;

    if (!str_ok(str) || !delim || !str_ok(lhs) || !str_ok(rhs))
        return -1;

    str_clear(lhs);
    str_clear(rhs);

    /* Set pointers to start and end */
    start = __str_ptr(str);
    end = start + __str_len(str);

    /* Start at beginning of string */
    p = start;

    /* Get left-hand-side */
    {
        /* Skip over non-delimiters */
        while (*p)
        {
            if (strchr(delim, *p))
            {
                found = 1;
                break;
            }
            p++;
        }

        str_ncpy(lhs, start, (size_t)(p - start));
    }

    /* Fail if no delimiter characters found */
    if (!found)
        return -1;

    /* Skip delimiters */
    while (*p && strchr(delim, *p))
        p++;

    /* Get right-hand-side */
    if (p != end)
        str_ncpy(rhs, p, (size_t)(end - p));

    return 0;
}

MEM_INLINE int str_u64(str_t* str, uint64_t* u64)
{
    uint64_t x;
    char* end;

    if (!str_ok(str) || !u64)
        return -1;

    x = strtoull(str_ptr(str), &end, 10);

    if (!end || *end)
        return -1;

    *u64 = x;
    return 0;
}

MEM_INLINE int str_u32(str_t* str, unsigned int* u32)
{
    unsigned long x;
    char* end;

    if (!str_ok(str) || !u32)
        return -1;

    x = strtoul(str_ptr(str), &end, 10);

    if (!end || *end || x > UINT_MAX)
        return -1;

    *u32 = (unsigned int)x;
    return 0;
}

MEM_INLINE int str_u16(str_t* str, unsigned short* u16)
{
    unsigned long x;
    char* end;

    if (!str_ok(str) || !u16)
        return -1;

    x = strtoul(str_ptr(str), &end, 10);

    if (!end || *end || x > USHRT_MAX)
        return -1;

    *u16 = (unsigned short)x;
    return 0;
}

#endif /* _OE_STR_H */
