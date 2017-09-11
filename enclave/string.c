#include <openenclave/enclave.h>

/*
**==============================================================================
**
** OE_Strlen()
** OE_Strcmp()
** OE_Strcpy()
** OE_Strlcpy()
** OE_Strlcat()
**
**==============================================================================
*/

size_t OE_Strlen(const char* s)
{
    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    while (*p)
        p++;

    return p - s;
}

int OE_Strcmp(const char* s1, const char* s2)
{
    while (*s1 && *s2)
    {
        int r = *s1++ - *s2++;

        if (r)
            return r;
    }

    if (*s1)
        return 1;

    if (*s2)
        return -1;

    return 0;
}

size_t OE_Strlcpy(char* dest, const char* src, size_t size)
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

size_t OE_Strlcat(char* dest, const char* src, size_t size)
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
** OE_Memset()
** OE_Memcpy()
** OE_Memcmp()
**
**==============================================================================
*/

void *OE_Memcpy(void *dest, const void *src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

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

    while (n--)
        *p++ = *q++;

    return dest;
}

void *OE_Memset(void *s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

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

    while (n--)
        *p++ = c;

    return s;
}

int OE_Memcmp(const void *s1, const void *s2, size_t n)
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

/*
**==============================================================================
**
** OE_Vsnprintf()
**
**==============================================================================
*/

static char _NibbleToChar(uint64_t x)
{
    static char _table[] =
    {
        '0', '1', '2', '3', '4', '5', '6', '7', 
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    return _table[x & 0x000000000000000f];
}

static const char* _U32ToHexStr(char buf[9], uint32_t x)
{
    buf[0] = _NibbleToChar((0xf0000000 & x) >> 28);
    buf[1] = _NibbleToChar((0x0f000000 & x) >> 24);
    buf[2] = _NibbleToChar((0x00f00000 & x) >> 20);
    buf[3] = _NibbleToChar((0x000f0000 & x) >> 16);
    buf[4] = _NibbleToChar((0x0000f000 & x) >> 12);
    buf[5] = _NibbleToChar((0x00000f00 & x) >> 8);
    buf[6] = _NibbleToChar((0x000000f0 & x) >> 4);
    buf[7] = _NibbleToChar((0x0000000f & x));
    buf[8] = '\0';
    return buf;
}

static const char* _U64ToHexStr(char buf[17], uint64_t x)
{
    uint64_t hi = (0xffffffff00000000 & x) >> 32;
    uint64_t lo = (0x00000000ffffffff & x);

    _U32ToHexStr(buf, hi);
    _U32ToHexStr(buf+8, lo);

    return buf;
}

static const char* _U64ToStr(
    char buf[21],
    uint64_t x)
{
    char* end = &buf[21];

    *--end = '\0';

    if (x == 0)
    {
        *--end = '0';
        return end;
    }

    while (x)
    {
        uint64_t m = x % 10;
        *--end = m + '0';
        x = x / 10;
    }

    return end;
}

static const char* _S64ToStr(char buf[21], int64_t x)
{
    char* p;
    int neg = 0;

    if (x == (-9223372036854775807-1))
        return "-9223372036854775808";

    if (x < 0)
    {
        neg = 1;
        x = -x;
    }

    p = &buf[63];
    *p = '\0';

    do
    {
        *--p = '0' + x % 10;
    }
    while (x /= 10);

    if(neg)
        *--p = '-';


    return p;
}

int OE_Vsnprintf(char* str, size_t size, const char* fmt, OE_va_list ap)
{
    const char* p = fmt;
    bool overflow = false;
    size_t n = 0;

    if (str)
        *str = '\0';
    else
        overflow = true;

    while (*p)
    {
        char scratch[64];
        const char* s;

        if (*p == '%')
        {
            p++;

            if (p[0] == 's')
            {
                if (!(s = OE_va_arg(ap, const char*)))
                    s = "(null)";

                p++;
            }
            else if (p[0] == 'u')
            {
                s = _U64ToStr(scratch, OE_va_arg(ap, uint32_t));
                p++;
            }
            else if (p[0] == 'd')
            {
                s = _S64ToStr(scratch, OE_va_arg(ap, int32_t));
                p++;
            }
            else if (p[0] == 'x')
            {
                s = _U32ToHexStr(scratch, OE_va_arg(ap, uint32_t));
                p++;
            }
            else if (p[0] == 'l' && p[1] == 'u')
            {
                s = _U64ToStr(scratch, OE_va_arg(ap, uint64_t));
                p += 2;
            }
            else if (p[0] == 'l' && p[1] == 'd')
            {
                s = _S64ToStr(scratch, OE_va_arg(ap, int64_t));
                p += 2;
            }
            else if (p[0] == 'l' && p[1] == 'x')
            {
                s = _U64ToHexStr(scratch, OE_va_arg(ap, uint64_t));
                p += 2;
            }
            else if (p[0] == 'z' && p[1] == 'u')
            {
                s = _U64ToStr(scratch, OE_va_arg(ap, size_t));
                p += 2;
            }
            else if (p[0] == 'z' && p[1] == 'd')
            {
                s = _S64ToStr(scratch, OE_va_arg(ap, ssize_t));
                p += 2;
            }
            else if (p[0] == 'p')
            {
                s = _U64ToStr(scratch, (uint64_t)OE_va_arg(ap, void*));
                p += 1;
            }
            else
            {
                return -1;
            }
        }
        else
        {
            scratch[0] = *p++;
            scratch[1] = '\0';
            s = scratch;
        }

        if (overflow)
        {
            n += OE_Strlen(s);
        }
        else
        {
            n = OE_Strlcat(str, s, size);

            if (n >= size)
                overflow = true;
        }
    }

    return n;
}

int OE_Snprintf(char* str, size_t size, const char* fmt, ...)
{
    OE_va_list ap;
    OE_va_start(ap, fmt);
    int n = OE_Vsnprintf(str, size, fmt, ap);
    OE_va_end(ap);
    return n;
}
