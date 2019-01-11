/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "ctype_optee_t.h"

int isspace(int c)
{
    return (c == 0x20 || ((c >= 0x09) && (c <= 0x0d)));
}

int isupper(int c)
{
    return ((c >= 'A') && (c <= 'Z'));
}

int islower(int c)
{
    return ((c >= 'a') && (c <= 'z'));
}

int isalpha(int c)
{
    return isupper(c) || islower(c);
}

int isdigit(int c) 
{
    return ((c >= '0') && (c <= '9'));
}

int isxdigit(int c) 
{
    return isdigit(c) || ((c >= 'A') && (c <= 'F')) || ((c >= 'a') && (c <= 'f'));
}

int isalnum(int c)
{
    return isdigit(c) || isalpha(c);
}

int tolower(int c)
{
    if (!isupper(c)) {
        return c;
    }
    return c - 'A' + 'a';
}

#define __ascii_toupper(c)      ( (((c) >= 'a') && ((c) <= 'z')) ? ((c) - 'a' + 'A') : (c) )

int toupper(int const c)
{
    return __ascii_toupper(c);
}
