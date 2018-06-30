// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_STRING_H
#define _OE_ENCLAVELIBC_STRING_H

#include "bits/common.h"

OE_ENCLAVELIBC_EXTERNC_BEGIN

size_t oe_strlen(const char* s);

size_t oe_strnlen(const char* s, size_t n);

int oe_strcmp(const char* s1, const char* s2);

int oe_strncmp(const char* s1, const char* s2, size_t n);

char* oe_strncpy(char* dest, const char* src, size_t n);

char* oe_strstr(const char* haystack, const char* needle);

void* oe_memset(void* s, int c, size_t n);

void* oe_memcpy(void* dest, const void* src, size_t n);

int oe_memcmp(const void* s1, const void* s2, size_t n);

void* oe_memmove(void* dest, const void* src, size_t n);

size_t oe_strlcpy(char* dest, const char* src, size_t size);

size_t oe_strlcat(char* dest, const char* src, size_t size);

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

OE_ENCLAVELIBC_INLINE
size_t strlen(const char* s)
{
    return oe_strlen(s);
}

OE_ENCLAVELIBC_INLINE
size_t strnlen(const char* s, size_t n)
{
    return oe_strnlen(s, n);
}

OE_ENCLAVELIBC_INLINE
int strcmp(const char* s1, const char* s2)
{
    return oe_strcmp(s1, s2);
}

OE_ENCLAVELIBC_INLINE
int strncmp(const char* s1, const char* s2, size_t n)
{
    return oe_strncmp(s1, s2, n);
}

OE_ENCLAVELIBC_INLINE
char* strncpy(char* dest, const char* src, size_t n)
{
    return oe_strncpy(dest, src, n);
}

OE_ENCLAVELIBC_INLINE
char* strstr(const char* haystack, const char* needle)
{
    return oe_strstr(haystack, needle);
}

OE_ENCLAVELIBC_INLINE
void* memset(void* s, int c, size_t n)
{
    return oe_memset(s, c, n);
}

OE_ENCLAVELIBC_INLINE
void* memcpy(void* dest, const void* src, size_t n)
{
    return oe_memcpy(dest, src, n);
}

OE_ENCLAVELIBC_INLINE
int memcmp(const void* s1, const void* s2, size_t n)
{
    return oe_memcmp(s1, s2, n);
}

OE_ENCLAVELIBC_INLINE
void* memmove(void* dest, const void* src, size_t n)
{
    return oe_memmove(dest, src, n);
}

OE_ENCLAVELIBC_INLINE
size_t strlcpy(char* dest, const char* src, size_t size)
{
    return oe_strlcpy(dest, src, size);
}

OE_ENCLAVELIBC_INLINE
size_t strlcat(char* dest, const char* src, size_t size)
{
    return oe_strlcat(dest, src, size);
}

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

OE_ENCLAVELIBC_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_STRING_H */
