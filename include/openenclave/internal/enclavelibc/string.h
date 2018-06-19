// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STRING_H
#define _ENCLAVELIBC_STRING_H

#include "bits/common.h"

ENCLAVELIBC_INLINE 
size_t strlen(const char* s)
{
    return __enclavelibc.strlen(s);
}

ENCLAVELIBC_INLINE 
int strcmp(const char* s1, const char* s2)
{
    return __enclavelibc.strcmp(s1, s2);
}

ENCLAVELIBC_INLINE 
int strncmp(const char* s1, const char* s2, size_t n)
{
    return __enclavelibc.strncmp(s1, s2, n);
}

ENCLAVELIBC_INLINE
char* strncpy(char* dest, const char* src, size_t n)
{
    return __enclavelibc.strncpy(dest, src, n);
}

ENCLAVELIBC_INLINE 
char* strstr(const char* haystack, const char* needle)
{
    return __enclavelibc.strstr(haystack, needle);
}

ENCLAVELIBC_INLINE 
void* memset(void* s, int c, size_t n)
{
    return __enclavelibc.memset(s, c, n);
}

ENCLAVELIBC_INLINE 
void* memcpy(void* dest, const void* src, size_t n)
{
    return __enclavelibc.memcpy(dest, src, n);
}

ENCLAVELIBC_INLINE 
int memcmp(const void* s1, const void* s2, size_t n)
{
    return __enclavelibc.memcmp(s1, s2, n);
}

ENCLAVELIBC_INLINE 
void* memmove(void* dest, const void* src, size_t n)
{
    return __enclavelibc.memmove(dest, src, n);
}

ENCLAVELIBC_INLINE 
int rand(void)
{
    return __enclavelibc.rand();
}

#endif /* _ENCLAVELIBC_STRING_H */
