// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_STRING_H
#define _ELIBC_STRING_H

#include "bits/common.h"

ELIBC_EXTERNC_BEGIN

size_t elibc_strlen(const char* s);

size_t elibc_strnlen(const char* s, size_t n);

int elibc_strcmp(const char* s1, const char* s2);

int elibc_strncmp(const char* s1, const char* s2, size_t n);

int elibc_strcasecmp(const char* s1, const char* s2);

int elibc_strncasecmp(const char* s1, const char* s2, size_t n);

char* elibc_strcpy(char* dest, const char* src);

char* elibc_strncpy(char* dest, const char* src, size_t n);

char* elibc_strcat(char* dest, const char* src);

char* elibc_strncat(char* dest, const char* src, size_t n);

char* elibc_strchr(const char* s, int c);

char* elibc_strrchr(const char* s, int c);

char* elibc_index(const char* s, int c);

char* elibc_rindex(const char* s, int c);

char* elibc_strstr(const char* haystack, const char* needle);

void* elibc_memset(void* s, int c, size_t n);

void* elibc_memcpy(void* dest, const void* src, size_t n);

int elibc_memcmp(const void* s1, const void* s2, size_t n);

void* elibc_memmove(void* dest, const void* src, size_t n);

size_t elibc_strlcpy(char* dest, const char* src, size_t size);

size_t elibc_strlcat(char* dest, const char* src, size_t size);

char* elibc_strdup(const char* s);

char* elibc_strndup(const char* s, size_t n);

char* elibc_strerror(int errnum);

int elibc_strerror_r(int errnum, char* buf, size_t buflen);

#if defined(ELIBC_NEED_STDC_NAMES)

ELIBC_INLINE
size_t strlen(const char* s)
{
    return elibc_strlen(s);
}

ELIBC_INLINE
size_t strnlen(const char* s, size_t n)
{
    return elibc_strnlen(s, n);
}

ELIBC_INLINE
int strcmp(const char* s1, const char* s2)
{
    return elibc_strcmp(s1, s2);
}

ELIBC_INLINE
int strcasecmp(const char* s1, const char* s2)
{
    return elibc_strcasecmp(s1, s2);
}

ELIBC_INLINE
int strncasecmp(const char* s1, const char* s2, size_t n)
{
    return elibc_strncasecmp(s1, s2, n);
}

ELIBC_INLINE
int strncmp(const char* s1, const char* s2, size_t n)
{
    return elibc_strncmp(s1, s2, n);
}

ELIBC_INLINE
char* strcpy(char* dest, const char* src)
{
    return elibc_strcpy(dest, src);
}

ELIBC_INLINE
char* strncpy(char* dest, const char* src, size_t n)
{
    return elibc_strncpy(dest, src, n);
}

ELIBC_INLINE
char* strcat(char* dest, const char* src)
{
    return elibc_strcat(dest, src);
}

ELIBC_INLINE
char* strncat(char* dest, const char* src, size_t n)
{
    return elibc_strncat(dest, src, n);
}

ELIBC_INLINE
char* strchr(const char* s, int c)
{
    return elibc_strchr(s, c);
}

ELIBC_INLINE
char* strrchr(const char* s, int c)
{
    return elibc_strrchr(s, c);
}

ELIBC_INLINE
char* index(const char* s, int c)
{
    return elibc_index(s, c);
}

ELIBC_INLINE
char* rindex(const char* s, int c)
{
    return elibc_rindex(s, c);
}

ELIBC_INLINE
char* strstr(const char* haystack, const char* needle)
{
    return elibc_strstr(haystack, needle);
}

ELIBC_INLINE
void* memset(void* s, int c, size_t n)
{
    return elibc_memset(s, c, n);
}

ELIBC_INLINE
void* memcpy(void* dest, const void* src, size_t n)
{
    return elibc_memcpy(dest, src, n);
}

ELIBC_INLINE
int memcmp(const void* s1, const void* s2, size_t n)
{
    return elibc_memcmp(s1, s2, n);
}

ELIBC_INLINE
void* memmove(void* dest, const void* src, size_t n)
{
    return elibc_memmove(dest, src, n);
}

ELIBC_INLINE
size_t strlcpy(char* dest, const char* src, size_t size)
{
    return elibc_strlcpy(dest, src, size);
}

ELIBC_INLINE
size_t strlcat(char* dest, const char* src, size_t size)
{
    return elibc_strlcat(dest, src, size);
}

ELIBC_INLINE
char* strdup(const char* s)
{
    return elibc_strdup(s);
}

ELIBC_INLINE
char* strndup(const char* s, size_t n)
{
    return elibc_strndup(s, n);
}

ELIBC_INLINE
char* strerror(int errnum)
{
    return elibc_strerror(errnum);
}

ELIBC_INLINE
int strerror_r(int errnum, char* buf, size_t buflen)
{
    return elibc_strerror_r(errnum, buf, buflen);
}

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_STRING_H */
