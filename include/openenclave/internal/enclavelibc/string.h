// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STRING_H
#define _ENCLAVELIBC_STRING_H

#include "bits/common.h"

OE_INLINE 
size_t strlen(const char* s)
{
    return __enclavelibc.strlen(s);
}

OE_INLINE 
size_t strnlen(const char* s, size_t n)
{
    return __enclavelibc.strnlen(s, n);
}

OE_INLINE 
int strcmp(const char* s1, const char* s2)
{
    return __enclavelibc.strcmp(s1, s2);
}

OE_INLINE 
int strncmp(const char* s1, const char* s2, size_t n)
{
    return __enclavelibc.strncmp(s1, s2, n);
}

OE_INLINE
char* strncpy(char* dest, const char* src, size_t n)
{
    return __enclavelibc.strncpy(dest, src, n);
}

OE_INLINE 
char* strstr(const char* haystack, const char* needle)
{
    return __enclavelibc.strstr(haystack, needle);
}

OE_INLINE 
void* memset(void* s, int c, size_t n)
{
    return __enclavelibc.memset(s, c, n);
}

OE_INLINE 
void* memcpy(void* dest, const void* src, size_t n)
{
    return __enclavelibc.memcpy(dest, src, n);
}

OE_INLINE 
int memcmp(const void* s1, const void* s2, size_t n)
{
    return __enclavelibc.memcmp(s1, s2, n);
}

OE_INLINE 
void* memmove(void* dest, const void* src, size_t n)
{
    return __enclavelibc.memmove(dest, src, n);
}

OE_INLINE 
size_t strlcpy(char* dest, const char* src, size_t size)
{
    return __enclavelibc.strlcpy(dest, src, size);
}

OE_INLINE 
size_t strlcat(char* dest, const char* src, size_t size)
{
    return __enclavelibc.strlcat(dest, src, size);
}

#endif /* _ENCLAVELIBC_STRING_H */
