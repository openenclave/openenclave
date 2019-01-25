// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CTYPE_H
#define _OE_CTYPE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

#define __OE_ISALNUM_BIT (1 << 0)
#define __OE_ISALPHA_BIT (1 << 1)
#define __OE_ISCNTRL_BIT (1 << 2)
#define __OE_ISDIGIT_BIT (1 << 3)
#define __OE_ISGRAPH_BIT (1 << 4)
#define __OE_ISLOWER_BIT (1 << 5)
#define __OE_ISPRINT_BIT (1 << 6)
#define __OE_ISPUNCT_BIT (1 << 7)
#define __OE_ISSPACE_BIT (1 << 8)
#define __OE_ISUPPER_BIT (1 << 9)
#define __OE_ISXDIGIT_BIT (1 << 10)

extern const unsigned short* __oe_ctype_b_loc;

extern const unsigned int* __oe_ctype_tolower_loc;

extern const unsigned int* __oe_ctype_toupper_loc;

OE_INLINE
int oe_isalnum(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISALNUM_BIT;
}

OE_INLINE
int oe_isalpha(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISALPHA_BIT;
}

OE_INLINE
int oe_iscntrl(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISCNTRL_BIT;
}

OE_INLINE
int oe_isdigit(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISDIGIT_BIT;
}

OE_INLINE
int oe_isgraph(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISGRAPH_BIT;
}

OE_INLINE
int oe_islower(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISLOWER_BIT;
}

OE_INLINE
int oe_isprint(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISPRINT_BIT;
}

OE_INLINE
int oe_ispunct(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISPUNCT_BIT;
}

OE_INLINE
int oe_isspace(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISSPACE_BIT;
}

OE_INLINE
int oe_isupper(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISUPPER_BIT;
}

OE_INLINE
int oe_isxdigit(int c)
{
    return __oe_ctype_b_loc[c] & __OE_ISXDIGIT_BIT;
}

OE_INLINE
int oe_toupper(int c)
{
    return (int)__oe_ctype_toupper_loc[c];
}

OE_INLINE
int oe_tolower(int c)
{
    return (int)__oe_ctype_tolower_loc[c];
}

#if defined(OE_NEED_STDC_NAMES)

OE_INLINE
int isalnum(int c)
{
    return oe_isalnum(c);
}

OE_INLINE
int isalpha(int c)
{
    return oe_isalpha(c);
}

OE_INLINE
int iscntrl(int c)
{
    return oe_iscntrl(c);
}

OE_INLINE
int isdigit(int c)
{
    return oe_isdigit(c);
}

OE_INLINE
int isgraph(int c)
{
    return oe_isgraph(c);
}

OE_INLINE
int islower(int c)
{
    return oe_islower(c);
}

OE_INLINE
int isprint(int c)
{
    return oe_isprint(c);
}

OE_INLINE
int ispunct(int c)
{
    return oe_ispunct(c);
}

OE_INLINE
int isspace(int c)
{
    return oe_isspace(c);
}

OE_INLINE
int isupper(int c)
{
    return oe_isupper(c);
}

OE_INLINE
int isxdigit(int c)
{
    return oe_isxdigit(c);
}

OE_INLINE
int toupper(int c)
{
    return oe_toupper(c);
}

OE_INLINE
int tolower(int c)
{
    return oe_tolower(c);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_CTYPE_H */
