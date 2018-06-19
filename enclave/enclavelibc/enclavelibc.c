// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc/bits/common.h>

struct enclavelibc
{
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
    int (*vsnprintf)(char* str, size_t size, const char* format, oe_va_list ap);
    int (*vprintf)(const char* format, oe_va_list ap);
    oe_time_t (*time)(oe_time_t* tloc);
    struct oe_tm* (*gmtime)(const oe_time_t* timep);
    struct oe_tm* (*gmtime_r)(const oe_time_t* timep, struct oe_tm* result);
    int (*rand)(void);
    void* (*malloc)(size_t size);
    void (*free)(void* ptr);
    void* (*calloc)(size_t nmemb, size_t size);
    void* (*realloc)(void* ptr, size_t size);
    void* (*memalign)(size_t alignment, size_t size);
    int (*posix_memalign)(void** memptr, size_t alignment, size_t size);
    unsigned long int (*strtoul)(const char* nptr, char** endptr, int base);
};

const void* oe_link_enclavelibc(void)
{
    static const struct enclavelibc _enclavelibc = {
        .strlen = oe_strlen,
        .strnlen = oe_strnlen,
        .strcmp = oe_strcmp,
        .strncmp = oe_strncmp,
        .strncpy = oe_strncpy,
        .strstr = oe_strstr,
        .strlcpy = oe_strlcpy,
        .strlcat = oe_strlcat,
        .memcpy = oe_memcpy,
        .memset = oe_memset,
        .memcmp = oe_memcmp,
        .memmove = oe_memmove,
        .vsnprintf = oe_vsnprintf,
        .vprintf = oe_vprintf,
        .time = oe_time,
        .gmtime = oe_gmtime,
        .gmtime_r = oe_gmtime_r,
        .rand = oe_rand,
        .malloc = oe_malloc,
        .free = oe_free,
        .calloc = oe_calloc,
        .realloc = oe_realloc,
        .memalign = oe_memalign,
        .posix_memalign = oe_posix_memalign,
        .strtoul = oe_strtoul,
    };

    return &_enclavelibc;
}
