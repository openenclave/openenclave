// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>

static char _nibble_to_char(uint64_t x)
{
    static char _table[] = {'0',
                            '1',
                            '2',
                            '3',
                            '4',
                            '5',
                            '6',
                            '7',
                            '8',
                            '9',
                            'a',
                            'b',
                            'c',
                            'd',
                            'e',
                            'f'};

    return _table[x & 0x000000000000000f];
}

static const char* _u32_to_hex_str(char buf[9], uint32_t x)
{
    buf[0] = _nibble_to_char((0xf0000000 & x) >> 28);
    buf[1] = _nibble_to_char((0x0f000000 & x) >> 24);
    buf[2] = _nibble_to_char((0x00f00000 & x) >> 20);
    buf[3] = _nibble_to_char((0x000f0000 & x) >> 16);
    buf[4] = _nibble_to_char((0x0000f000 & x) >> 12);
    buf[5] = _nibble_to_char((0x00000f00 & x) >> 8);
    buf[6] = _nibble_to_char((0x000000f0 & x) >> 4);
    buf[7] = _nibble_to_char((0x0000000f & x));
    buf[8] = '\0';
    return buf;
}

static const char* _u64_to_hex_str(char buf[17], uint64_t x)
{
    uint64_t hi = (0xffffffff00000000 & x) >> 32;
    uint64_t lo = (0x00000000ffffffff & x);

    _u32_to_hex_str(buf, (uint32_t)hi);
    _u32_to_hex_str(buf + 8, (uint32_t)lo);

    return buf;
}

static const char* _u64_to_str(char buf[21], uint64_t x)
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
        *--end = (char)(m + '0');
        x = x / 10;
    }

    return end;
}

static const char* _s64_to_str(char buf[21], int64_t x)
{
    char* p;
    int neg = 0;

    if (x == (-9223372036854775807 - 1))
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
        *--p = (char)('0' + x % 10);
    } while (x /= 10);

    if (neg)
        *--p = '-';

    return p;
}

int oe_vsnprintf(char* str, size_t size, const char* fmt, oe_va_list ap)
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
                if (!(s = oe_va_arg(ap, const char*)))
                    s = "(null)";

                p++;
            }
            else if (p[0] == 'u')
            {
                s = _u64_to_str(scratch, oe_va_arg(ap, uint32_t));
                p++;
            }
            else if (p[0] == 'd')
            {
                s = _s64_to_str(scratch, oe_va_arg(ap, int32_t));
                p++;
            }
            else if (p[0] == 'x')
            {
                s = _u32_to_hex_str(scratch, oe_va_arg(ap, uint32_t));
                p++;
            }
            else if (p[0] == 'l' && p[1] == 'u')
            {
                s = _u64_to_str(scratch, oe_va_arg(ap, uint64_t));
                p += 2;
            }
            else if (p[0] == 'l' && p[1] == 'l' && p[2] == 'u')
            {
                s = _u64_to_str(scratch, oe_va_arg(ap, uint64_t));
                p += 3;
            }
            else if (p[0] == 'l' && p[1] == 'd')
            {
                s = _s64_to_str(scratch, oe_va_arg(ap, int64_t));
                p += 2;
            }
            else if (p[0] == 'l' && p[1] == 'l' && p[2] == 'd')
            {
                s = _s64_to_str(scratch, oe_va_arg(ap, int64_t));
                p += 3;
            }
            else if (p[0] == 'l' && p[1] == 'x')
            {
                s = _u64_to_hex_str(scratch, oe_va_arg(ap, uint64_t));
                p += 2;
            }
            else if (p[0] == 'l' && p[1] == 'x' && p[2] == 'x')
            {
                s = _u64_to_hex_str(scratch, oe_va_arg(ap, uint64_t));
                p += 3;
            }
            else if (p[0] == 'z' && p[1] == 'u')
            {
                s = _u64_to_str(scratch, oe_va_arg(ap, size_t));
                p += 2;
            }
            else if (p[0] == 'z' && p[1] == 'd')
            {
                s = _s64_to_str(scratch, oe_va_arg(ap, ssize_t));
                p += 2;
            }
            else if (p[0] == 'p')
            {
                s = _u64_to_hex_str(
                    scratch + 2, (uint64_t)oe_va_arg(ap, void*));
                ((char*)s)[-1] = 'x';
                ((char*)s)[-2] = '0';
                s -= 2;
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
            n += oe_strlen(s);
        }
        else
        {
            n = oe_strlcat(str, s, size);

            if (n >= size)
                overflow = true;
        }
    }

    if (n > OE_INT_MAX)
        return OE_INT_MAX;

    return (int)n;
}

int oe_snprintf(char* str, size_t size, const char* fmt, ...)
{
    oe_va_list ap;
    oe_va_start(ap, fmt);
    int n = oe_vsnprintf(str, size, fmt, ap);
    oe_va_end(ap);
    return n;
}
