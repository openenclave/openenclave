// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* DISCLAIMER:
 * This header is published with no guarantees of stability and is not part
 * of the Open Enclave public API surface. It is only intended to be used
 * internally by the OE runtime. */

#ifndef _OE_STRING_H
#define _OE_STRING_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/defs.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

/* The mem methods are always defined by their stdc names in oecore */
int memcmp(const void* vl, const void* vr, size_t n);
void* memcpy(void* OE_RESTRICT dest, const void* OE_RESTRICT src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
void* memset(void* dest, int c, size_t n);

size_t oe_strlen(const char* s);

int oe_strcmp(const char* s1, const char* s2);

int oe_strncmp(const char* s1, const char* s2, size_t n);

char* oe_strstr(const char* haystack, const char* needle);

size_t oe_strlcpy(char* dest, const char* src, size_t size);

size_t oe_strlcat(char* dest, const char* src, size_t size);

char* oe_strerror(int errnum);

int oe_strerror_r(int errnum, char* buf, size_t buflen);

char* oe_strtok_r(char* str, const char* delim, char** saveptr);

char* oe_strdup(const char* s);

size_t oe_strspn(const char* s, const char* accept);

size_t oe_strcspn(const char* s, const char* reject);

char* oe_strchr(const char* s, int c);

char* oe_strchrnul(const char* s, int c);

char* oe_strrchr(const char* s, int c);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

OE_INLINE
size_t strlen(const char* s)
{
    return oe_strlen(s);
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
char* strstr(const char* haystack, const char* needle)
{
    return oe_strstr(haystack, needle);
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

OE_INLINE
char* strerror(int errnum)
{
    return oe_strerror(errnum);
}

OE_INLINE
int strerror_r(int errnum, char* buf, size_t buflen)
{
    return oe_strerror_r(errnum, buf, buflen);
}

OE_INLINE
char* strtok_r(char* str, const char* delim, char** saveptr)
{
    return oe_strtok_r(str, delim, saveptr);
}

OE_INLINE char* strdup(const char* s)
{
    return oe_strdup(s);
}

OE_INLINE size_t strspn(const char* s, const char* accept)
{
    return oe_strspn(s, accept);
}

OE_INLINE size_t strcspn(const char* s, const char* reject)
{
    return oe_strcspn(s, reject);
}

OE_INLINE char* strchr(const char* s, int c)
{
    return oe_strchr(s, c);
}

OE_INLINE char* strchrnul(const char* s, int c)
{
    return oe_strchrnul(s, c);
}

OE_INLINE char* strrchr(const char* s, int c)
{
    return oe_strrchr(s, c);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_STRING_H */
