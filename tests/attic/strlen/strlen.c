#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#define HAS_ZERO_BYTE(x) (((x) - 0x01010101UL) & ~(x) & 0x80808080UL)
#define HAS_ZERO_BYTE(x) \
    (((x) - 0x0101010101010101UL) & ~(x) & 0x8080808080808080UL)

size_t Strlen(const char* s)
{
    return strlen(s);
}

size_t Strlen1(const char* s)
{
    const char* p = s;

    while (*p)
        p++;

    return p - s;
}

size_t Strlen2(const char* s)
{
    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] & p[5])
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

    return 0;
}

size_t Strlen3(const char* s)
{
    const char* p = s;

    /* Skip characters until pointer is aligned on 8-byte boundary */
    while ((uint64_t)p % 8)
    {
        /* Return size if end-of-string encountered */
        if (!*p)
            return p - s;

        p++;
    }

    /* Skip over 8-byte words until a word contains a zero byte */
    {
        const uint64_t* q = (const uint64_t*)p;

        while (!HAS_ZERO_BYTE(*q))
            q++;

        p = (const char*)q;
    }

    /* One of the next 8 bytes contains a zero-byte */
    {
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
        if (!p[6])
            return p - s + 6;
        if (!p[7])
            return p - s + 7;

        /* Unreachable! */
    }

    return p - s;
}
