/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "stdext.h"

#include <stdarg.h>

errno_t __attribute__((weak)) strcpy_s(char *__restrict dest, size_t destsz, const char *__restrict src)
{
    size_t i;
    if (!destsz)
        return EINVAL;
    if (!dest)
        return EINVAL;

    if (!src) {
        dest[0] = '\0';
        return EINVAL;
    }

    for (i = 0; i < destsz; i++) {
        if((dest[i] = src[i]) == '\0')
            return 0;
    }
    dest[0] = '\0';

    return ERANGE;
}

int __attribute__((weak)) sprintf_s(char * __restrict s, size_t n, const char * __restrict format, ...)
{
    va_list ap;
    
    va_start(ap, format);
    int result = vsnprintf(s, n, format, ap);
    va_end(ap);

    return result;
}

errno_t __attribute__((weak)) fopen_s(FILE **f, const char *name, const char *mode)
{
    errno_t ret = 0;
    
    if (!f)
        return EINVAL;
    
    *f = fopen(name, mode);
    
    if (!*f)
        ret = errno;
    
    return ret;
}
