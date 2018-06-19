// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>

static const unsigned char _digit[256] =
{
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0x00, /* '0' */
    0x01, /* '1' */
    0x02, /* '2' */
    0x03, /* '3' */
    0x04, /* '4' */
    0x05, /* '5' */
    0x06, /* '6' */
    0x07, /* '7' */
    0x08, /* '8' */
    0x09, /* '9' */
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0x0a, /* 'A' */
    0x0b, /* 'B' */
    0x0c, /* 'C' */
    0x0d, /* 'D' */
    0x0e, /* 'E' */
    0x0f, /* 'F' */
    0x10, /* 'G' */
    0x11, /* 'H' */
    0x12, /* 'I' */
    0x13, /* 'J' */
    0x14, /* 'K' */
    0x15, /* 'L' */
    0x16, /* 'M' */
    0x17, /* 'N' */
    0x18, /* 'O' */
    0x19, /* 'P' */
    0x1a, /* 'Q' */
    0x1b, /* 'R' */
    0x1c, /* 'S' */
    0x1d, /* 'T' */
    0x1e, /* 'U' */
    0x1f, /* 'V' */
    0x20, /* 'W' */
    0x21, /* 'X' */
    0x22, /* 'Y' */
    0x23, /* 'Z' */
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0x0a, /* 'a' */
    0x0b, /* 'b' */
    0x0c, /* 'c' */
    0x0d, /* 'd' */
    0x0e, /* 'e' */
    0x0f, /* 'f' */
    0x10, /* 'g' */
    0x11, /* 'h' */
    0x12, /* 'i' */
    0x13, /* 'j' */
    0x14, /* 'k' */
    0x15, /* 'l' */
    0x16, /* 'm' */
    0x17, /* 'n' */
    0x18, /* 'o' */
    0x19, /* 'p' */
    0x1a, /* 'q' */
    0x1b, /* 'r' */
    0x1c, /* 's' */
    0x1d, /* 't' */
    0x1e, /* 'u' */
    0x1f, /* 'v' */
    0x20, /* 'w' */
    0x21, /* 'x' */
    0x22, /* 'y' */
    0x23, /* 'z' */
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
};

OE_INLINE bool _isdigit(char c, int base)
{
    return _digit[(unsigned char)c] < base;
}

OE_INLINE bool _isspace(char c)
{
    return c == ' ' || c == '\t' || c == '\n';
}

unsigned long int oe_strtoul(const char* nptr, char** endptr, int base)
{
    const char* p;
    uint64_t x = 0;
    bool negative = false;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr)
        return 0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (_isspace(*p))
        p++;

    /* Handle '+' and '-' */
    if (p[0] == '+')
    {
        p++;
    }
    else if (p[0] == '-')
    {
        negative = true;
        p++;
    }

    /* Handle case where base == 0 */
    if (base == 0)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            base = 16;
            p += 2;
        }
        else if (p[0] == '0')
        {
            base = 8;
            p++;
        }
        else
        {
            base = 10;
        }
    }

    for (; *p && _isdigit(*p, base); p++)
    {
        /* Multiply by base */
        {
            /* Check for overflow */
            if (x > OE_MAX_UINT64 / base)
            {
                if (endptr)
                    *endptr = (char*)p;

                return OE_MAX_UINT64;
            }

            x = x * base;
        }

        /* Add digit */
        {
            const uint64_t digit = _digit[(unsigned char)*p];

            /* Check for overflow */
            if (digit > OE_MAX_UINT64 - x)
            {
                if (endptr)
                    *endptr = (char*)p;

                return OE_MAX_UINT64;
            }

            x += digit;
        }
    }

    /* Return zero if no digits were found */
    if (p == nptr)
        return 0;
    
    if (endptr)
        *endptr = (char*)p;

    /* Invert if negative */
    if (negative)
    {
        x = -x;
    }

    return x;
}
