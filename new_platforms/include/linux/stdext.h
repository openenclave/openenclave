/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#ifndef __STDC_LIB_EXT1__
  typedef int errno_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif
errno_t strcpy_s(char *__restrict dest, size_t destsz, const char *__restrict src);
int sprintf_s(char * __restrict s, size_t n, const char * __restrict format, ...);
errno_t fopen_s(FILE **f, const char *name, const char *mode);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
template <size_t destsz>
int __attribute__((weak)) strcpy_s(
   char (&dest)[destsz],
   const char *src
)
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
        if ((dest[i] = src[i]) == '\0')
            return 0;
    }
    dest[0] = '\0';

    return ERANGE;
}
#endif
