// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_CTYPE_H
#define _ELIBC_CTYPE_H

#include "bits/common.h"

#define __ELIBC_ISALNUM_BIT (1 << 0)
#define __ELIBC_ISALPHA_BIT (1 << 1)
#define __ELIBC_ISCNTRL_BIT (1 << 2)
#define __ELIBC_ISDIGIT_BIT (1 << 3)
#define __ELIBC_ISGRAPH_BIT (1 << 4)
#define __ELIBC_ISLOWER_BIT (1 << 5)
#define __ELIBC_ISPRINT_BIT (1 << 6)
#define __ELIBC_ISPUNCT_BIT (1 << 7)
#define __ELIBC_ISSPACE_BIT (1 << 8)
#define __ELIBC_ISUPPER_BIT (1 << 9)
#define __ELIBC_ISXDIGIT_BIT (1 << 10)

extern const unsigned short* __elibc_ctype_b_loc;

extern const unsigned int* __elibc_ctype_tolower_loc;

extern const unsigned int* __elibc_ctype_toupper_loc;

ELIBC_INLINE
int elibc_isalnum(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISALNUM_BIT;
}

ELIBC_INLINE
int elibc_isalpha(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISALPHA_BIT;
}

ELIBC_INLINE
int elibc_iscntrl(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISCNTRL_BIT;
}

ELIBC_INLINE
int elibc_isdigit(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISDIGIT_BIT;
}

ELIBC_INLINE
int elibc_isgraph(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISGRAPH_BIT;
}

ELIBC_INLINE
int elibc_islower(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISLOWER_BIT;
}

ELIBC_INLINE
int elibc_isprint(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISPRINT_BIT;
}

ELIBC_INLINE
int elibc_ispunct(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISPUNCT_BIT;
}

ELIBC_INLINE
int elibc_isspace(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISSPACE_BIT;
}

ELIBC_INLINE
int elibc_isupper(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISUPPER_BIT;
}

ELIBC_INLINE
int elibc_isxdigit(int c)
{
    return __elibc_ctype_b_loc[c] & __ELIBC_ISXDIGIT_BIT;
}

ELIBC_INLINE
int elibc_toupper(int c)
{
    return __elibc_ctype_toupper_loc[c];
}

ELIBC_INLINE
int elibc_tolower(int c)
{
    return __elibc_ctype_tolower_loc[c];
}

#if defined(ELIBC_NEED_STDC_NAMES)

ELIBC_INLINE
int isalnum(int c)
{
    return elibc_isalnum(c);
}

ELIBC_INLINE
int isalpha(int c)
{
    return elibc_isalpha(c);
}

ELIBC_INLINE
int iscntrl(int c)
{
    return elibc_iscntrl(c);
}

ELIBC_INLINE
int isdigit(int c)
{
    return elibc_isdigit(c);
}

ELIBC_INLINE
int isgraph(int c)
{
    return elibc_isgraph(c);
}

ELIBC_INLINE
int islower(int c)
{
    return elibc_islower(c);
}

ELIBC_INLINE
int isprint(int c)
{
    return elibc_isprint(c);
}

ELIBC_INLINE
int ispunct(int c)
{
    return elibc_ispunct(c);
}

ELIBC_INLINE
int isspace(int c)
{
    return elibc_isspace(c);
}

ELIBC_INLINE
int isupper(int c)
{
    return elibc_isupper(c);
}

ELIBC_INLINE
int isxdigit(int c)
{
    return elibc_isxdigit(c);
}

ELIBC_INLINE
int toupper(int c)
{
    return elibc_toupper(c);
}

ELIBC_INLINE
int tolower(int c)
{
    return elibc_tolower(c);
}

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

#endif /* _ELIBC_CTYPE_H */
