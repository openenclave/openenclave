// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_COMMON_H
#define _ENCLAVELIBC_COMMON_H

#include "../../enclavelibc.h"

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#define CHAR_BIT 8

typedef long time_t;
typedef __builtin_va_list va_list;
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
    /* <string.h> */
    size_t (*strlen)(const char* s);
    size_t (*strnlen)(const char* s, size_t n);
    int (*strcmp)(const char* s1, const char* s2);
    int (*strncmp)(const char* s1, const char* s2, size_t n);
    char* (*strncpy)(char* dest, const char* src, size_t n);
    char* (*strstr)(const char* haystack, const char* needle);
    size_t (*strlcpy)(char* dest, const char* src, size_t size);
    size_t (*strlcat)(char* dest, const char* src, size_t size);
    void* (*memcpy)(void* dest, const void* src, size_t n);
    void* (*memset)(void* s, int c, size_t n);
    int (*memcmp)(const void* s1, const void* s2, size_t n);
    void* (*memmove)(void* dest, const void* src, size_t n);

    /* <stdio.h> */
    int (*vsnprintf)(char* str, size_t size, const char* format, va_list ap);
    int (*vprintf)(const char* format, va_list ap);

    /* <time.h> */
    time_t (*time)(time_t* tloc);
    struct tm* (*gmtime)(const time_t* timep);
    struct tm* (*gmtime_r)(const time_t* timep, struct tm* result);

    /* <stdlib.h> */
    int (*rand)(void);
    void* (*malloc)(size_t size);
    void (*free)(void* ptr);
    void* (*calloc)(size_t nmemb, size_t size);
    void* (*realloc)(void* ptr, size_t size);
    void* (*memalign)(size_t alignment, size_t size);
    int (*posix_memalign)(void** memptr, size_t alignment, size_t size);
}
enclavelibc_t;

extern enclavelibc_t __enclavelibc;

#endif /* _ENCLAVELIBC_COMMON_H */
