// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_COMMON_H
#define _ENCLAVELIBC_COMMON_H

#include "../../enclavelibc.h"

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#define CHAR_BIT 8

#define ENCLAVELIBC_INLINE static __inline

typedef oe_time_t time_t;
typedef oe_va_list va_list;
typedef long suseconds_t;
typedef int clockid_t;

struct timeval 
{
   time_t tv_sec;
   suseconds_t tv_usec;
};

struct timezone 
{
   int tz_minuteswest;
   int tz_dsttime;
};

typedef struct _enclavelibc
{
    size_t (*strlen)(const char* s);
    int (*strcmp)(const char* s1, const char* s2);
    int (*strncmp)(const char* s1, const char* s2, size_t n);
    char* (*strncpy)(char* dest, const char* src, size_t n);
    char* (*strstr)(const char* haystack, const char* needle);
    void* (*memset)(void* s, int c, size_t n);
    void* (*memcpy)(void* dest, const void* src, size_t n);
    int (*memcmp)(const void* s1, const void* s2, size_t n);
    void* (*memmove)(void* dest, const void* src, size_t n);
    void* (*malloc)(size_t size);
    void (*free)(void* ptr);
    void* (*calloc)(size_t nmemb, size_t size);
    void* (*realloc)(void* ptr, size_t size);
    int (*vsnprintf)(char* str, size_t size, const char* format, va_list ap);
    int (*vprintf)(const char* format, va_list ap);
    int (*rand)(void);
    time_t (*time)(time_t* tloc);
    struct tm* (*gmtime)(const time_t* timep);
}
enclavelibc_t;

extern enclavelibc_t __enclavelibc;

#endif /* _ENCLAVELIBC_COMMON_H */
