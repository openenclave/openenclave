// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/ctype.h>
#include <openenclave/corelibc/stdlib.h>

//
// If c is a digit character:
//     then: _digit[c] yields the integer value for that digit character.
//     else: _digit[c] yields 0xFF.
//
// Digit characters fall within these ranges: ['0'-'9'] and ['A'-'Z'].
//
// Examples:
//     _digit['9'] => 9
//     _digit['A'] => 10
//     _digit['Z'] => 35
//     _digit['?'] => 0xFF
//
static const unsigned char _digit[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
};

/* Return true if c is a digit character within the given base */
OE_INLINE bool _isdigit(char c, int base)
{
    return _digit[(unsigned char)c] < base;
}

unsigned long int oe_strtoul(const char* nptr, char** endptr, int base)
{
    const char* p;
    unsigned long x = 0;
    bool negative = false;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr || base < 0)
        return 0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (oe_isspace(*p))
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

    /* If base is zero, deduce the base from the prefix. */
    if (base == 0)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            base = 16;
        }
        else if (p[0] == '0')
        {
            base = 8;
        }
        else
        {
            base = 10;
        }
    }

    /* Remove any base 16 prefix. */
    if (base == 16)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
        }
    }

    /* Remove any base 8 prefix. */
    if (base == 8)
    {
        if (p[0] == '0')
        {
            p++;
        }
    }

    for (; *p && _isdigit(*p, base); p++)
    {
        /* Multiply by base */
        {
            /* Check for overflow */
            if (x > OE_UINT64_MAX / (unsigned long)base)
            {
                if (endptr)
                    *endptr = (char*)p;

                return OE_UINT64_MAX;
            }

            x = x * (unsigned long)base;
        }

        /* Add digit */
        {
            const unsigned long digit = _digit[(unsigned char)*p];

            /* Check for overflow */
            if (digit > OE_ULONG_MAX - x)
            {
                if (endptr)
                    *endptr = (char*)p;

                return OE_UINT64_MAX;
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
        if (x > OE_LONG_MAX)
        {
            if (x == (unsigned long)OE_LONG_MAX + 1)
                return x;
            else
                return 0;
        }
        x = (unsigned long)-(long)x;
    }

    return x;
}

/*
**==============================================================================
**
** Use the following functions to generate the _digit[] table above.
**
**==============================================================================
*/

#if defined(OE_NEED_STRTOUL_GENERATOR)

void __oe_gen_strtoul_table(void)
{
    for (int i = 0; i < 256; i++)
    {
        if (i >= '0' && i <= '9')
        {
            oe_printf("0x%02x,\n", i - '0');
        }
        else if (i >= 'A' && i <= 'Z')
        {
            oe_printf("0x%02x,\n", i - 'A' + 10);
        }
        else if (i >= 'a' && i <= 'z')
        {
            oe_printf("0x%02x,\n", i - 'a' + 10);
        }
        else
        {
            oe_printf("0xFF,\n");
        }
    }
}

#endif /* defined(OE_NEED_STRTOUL_GENERATOR) */
