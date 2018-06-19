// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STRING_H
#define _ENCLAVELIBC_STRING_H

#include "bits/common.h"

OE_INLINE
size_t strlen(const char* s)
{
    return oe_strlen(s);
}

OE_INLINE
size_t strnlen(const char* s, size_t n)
{
    return oe_strnlen(s, n);
}

OE_INLINE
int strcmp(const char* s1, const char* s2)
{
    return oe_strcmp(s1, s2);
}

OE_INLINE
int strncmp(const char* s1, const char* s2, size_t n)
{
    return oe_strncmp(s1, s2, n);
}

OE_INLINE
char* strncpy(char* dest, const char* src, size_t n)
{
    return oe_strncpy(dest, src, n);
}

OE_INLINE
char* strstr(const char* haystack, const char* needle)
{
    return oe_strstr(haystack, needle);
}

OE_INLINE
void* memset(void* s, int c, size_t n)
{
    return oe_memset(s, c, n);
}

OE_INLINE
void* memcpy(void* dest, const void* src, size_t n)
{
    return oe_memcpy(dest, src, n);
}

OE_INLINE
int memcmp(const void* s1, const void* s2, size_t n)
{
    return oe_memcmp(s1, s2, n);
}

OE_INLINE
void* memmove(void* dest, const void* src, size_t n)
{
    return oe_memmove(dest, src, n);
}

OE_INLINE
size_t strlcpy(char* dest, const char* src, size_t size)
{
    return oe_strlcpy(dest, src, size);
}

OE_INLINE
size_t strlcat(char* dest, const char* src, size_t size)
{
    return oe_strlcat(dest, src, size);
}

#endif /* _ENCLAVELIBC_STRING_H */
