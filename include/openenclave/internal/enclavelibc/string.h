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

int oe_strcasecmp(const char* s1, const char* s2);

int oe_strncasecmp(const char* s1, const char* s2, size_t n);

char* oe_strcpy(char* dest, const char* src);

char* oe_strncpy(char* dest, const char* src, size_t n);

char* oe_strcat(char* dest, const char* src);

char* oe_strncat(char* dest, const char* src, size_t n);

char* oe_strchr(const char* s, int c);

char* oe_strrchr(const char* s, int c);

char* oe_index(const char* s, int c);

char* oe_rindex(const char* s, int c);

char* oe_strstr(const char* haystack, const char* needle);

void* oe_memset(void* s, int c, size_t n);

void* oe_memcpy(void* dest, const void* src, size_t n);

int oe_memcmp(const void* s1, const void* s2, size_t n);

void* oe_memmove(void* dest, const void* src, size_t n);

size_t oe_strlcpy(char* dest, const char* src, size_t size);

size_t oe_strlcat(char* dest, const char* src, size_t size);

char* oe_strerror(int errnum);

int oe_strerror_r(int errnum, char* buf, size_t buflen);

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
int strcasecmp(const char* s1, const char* s2)
{
    return oe_strcasecmp(s1, s2);
}

OE_ENCLAVELIBC_INLINE
int strncasecmp(const char* s1, const char* s2, size_t n)
{
    return oe_strncasecmp(s1, s2, n);
}

OE_ENCLAVELIBC_INLINE
int strncmp(const char* s1, const char* s2, size_t n)
{
    return oe_strncmp(s1, s2, n);
}

OE_ENCLAVELIBC_INLINE
char* strcpy(char* dest, const char* src)
{
    return oe_strcpy(dest, src);
}

OE_ENCLAVELIBC_INLINE
char* strncpy(char* dest, const char* src, size_t n)
{
    return oe_strncpy(dest, src, n);
}

OE_ENCLAVELIBC_INLINE
char* strcat(char* dest, const char* src)
{
    return oe_strcat(dest, src);
}

OE_ENCLAVELIBC_INLINE
char* strncat(char* dest, const char* src, size_t n)
{
    return oe_strncat(dest, src, n);
}

OE_ENCLAVELIBC_INLINE
char* strchr(const char* s, int c)
{
    return oe_strchr(s, c);
}

OE_ENCLAVELIBC_INLINE
char* strrchr(const char* s, int c)
{
    return oe_strrchr(s, c);
}

OE_ENCLAVELIBC_INLINE
char* index(const char* s, int c)
{
    return oe_index(s, c);
}

OE_ENCLAVELIBC_INLINE
char* rindex(const char* s, int c)
{
    return oe_rindex(s, c);
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

OE_ENCLAVELIBC_INLINE
char* strerror(int errnum)
{
    return oe_strerror(errnum);
}

OE_ENCLAVELIBC_INLINE
int strerror_r(int errnum, char* buf, size_t buflen)
{
    return oe_strerror_r(errnum, buf, buflen);
}

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

OE_ENCLAVELIBC_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_STRING_H */
