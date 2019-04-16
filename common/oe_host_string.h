// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_STRING_H
#define _OE_HOST_STRING_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#if defined(WIN32) /* __feature_io__ */
int strerror_r(int errnum, char* buf, size_t buflen);
#endif

OE_INLINE
size_t oe_strlen(const char* s)
{
    return strlen(s);
}

OE_INLINE
size_t oe_strnlen(const char* s, size_t n)
{
    return strnlen(s, n);
}

OE_INLINE
int oe_strcmp(const char* s1, const char* s2)
{
    return strcmp(s1, s2);
}

OE_INLINE

int oe_strncmp(const char* s1, const char* s2, size_t n)
{
    return strncmp(s1, s2, n);
}

/* host already has an oe_strlcpy implementation */

/* host already has an oe_strlcat implementation */

OE_INLINE
char* oe_strerror(int errnum)
{
    return strerror(errnum);
}

OE_INLINE
int oe_strerror_r(int errnum, char* buf, size_t buflen)
{
#if defined(__GNUC__)
    /* GNUC version of strerror_r returns char* instead
     * caller is responsible for validating the output buf.
     * It should never return NULL.
     */
    if (!strerror_r(errnum, buf, buflen))
        return -1;
    return 0;
#else
    return strerror_r(errnum, buf, buflen);
#endif
}

OE_EXTERNC_END

#endif /* _OE_HOST_STRING_H */
