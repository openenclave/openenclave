#include <openenclave/enclave.h>

static char _NibbleToChar(uint64_t x)
{
    switch (x)
    {
        case 0x0: return '0';
        case 0x1: return '1';
        case 0x2: return '2';
        case 0x3: return '3';
        case 0x4: return '4';
        case 0x5: return '5';
        case 0x6: return '6';
        case 0x7: return '7';
        case 0x8: return '8';
        case 0x9: return '9';
        case 0xA: return 'a';
        case 0xB: return 'b';
        case 0xC: return 'c';
        case 0xD: return 'd';
        case 0xE: return 'e';
        case 0xF: return 'f';
    }

    return 0;
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

static const char* _U32ToStr(char buf[11], uint32_t x)
{
    char* end = &buf[11];

    *--end = '\0';

    if (x == 0)
    {
        *--end = '0';
        return end;
    }

    while (x)
    {
        uint32_t m = x % 10;
        *--end = m + '0';
        x = x / 10;
    }

    return end;
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

static const char* _S32ToStr(char buf[12], int32_t x)
{
    char* p;
    int neg = 0;

    if (x == (-2147483647-1))
        return "-2147483648";

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

    if (!str)
        return -1;

    *str = '\0';

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
                s = _U32ToStr(scratch, OE_va_arg(ap, uint32_t));
                p++;
            }
            else if (p[0] == 'd')
            {
                s = _S32ToStr(scratch, OE_va_arg(ap, int32_t));
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

        size_t n = OE_Strlcat(str, s, size);

        if (n >= size)
            return n;
    }

    return 0;
}
