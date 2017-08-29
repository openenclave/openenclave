#ifndef __ELIBC_ALLTYPES_H
#define __ELIBC_ALLTYPES_H

#ifndef NULL
# ifdef __cplusplus
#  define NULL 0L
# else
#  define NULL ((void*)0)
# endif
#endif

typedef int pid_t;

typedef int uid_t;

typedef int gid_t;

typedef long ssize_t;

typedef unsigned long size_t;

typedef struct __locale_struct *locale_t;

typedef struct _Dl_info Dl_info;

typedef double double_t;

typedef float float_t;

#if !defined(__cplusplus)
typedef int wchar_t;
#endif

typedef unsigned long wctype_t;

typedef const int *wctrans_t;

#ifndef __cplusplus
typedef unsigned short char16_t;
#endif

#ifndef __cplusplus
typedef unsigned int char32_t;
#endif

typedef long ptrdiff_t;

typedef unsigned wint_t;

typedef unsigned long size_t;
typedef long ssize_t;

typedef long off_t;

typedef signed char int8_t;

typedef unsigned char uint8_t;

typedef short int16_t;

typedef unsigned short uint16_t;

typedef int int32_t;

typedef unsigned int uint32_t;

typedef long int64_t;

typedef unsigned long uint64_t;

typedef unsigned long uintptr_t;

typedef long intptr_t;

typedef int32_t int_fast16_t;

typedef int32_t int_fast32_t;

typedef uint32_t uint_fast16_t;

typedef uint32_t uint_fast32_t;

typedef int64_t intmax_t;

typedef uint64_t uintmax_t;

typedef int8_t int_fast8_t;

typedef int64_t int_fast64_t;

typedef int8_t int_least8_t;

typedef int16_t int_least16_t;

typedef int32_t int_least32_t;

typedef int64_t int_least64_t;

typedef uint8_t uint_fast8_t;

typedef uint64_t uint_fast64_t;

typedef uint8_t uint_least8_t;

typedef uint16_t uint_least16_t;

typedef uint32_t uint_least32_t;

typedef uint64_t uint_least64_t;

typedef struct _sigset_t sigset_t;

typedef __builtin_va_list va_list;

typedef long time_t;

typedef long clock_t;

typedef int clockid_t;

typedef long suseconds_t;

typedef struct __mbstate_t 
{
    unsigned __field1;
    unsigned __field2; 
} 
mbstate_t;

typedef struct _IO_FILE FILE;

struct tm 
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long __tm_gmtoff;
    char *__tm_zone;
};

struct timespec 
{ 
    time_t tv_sec; 
    long tv_nsec; 
};

#endif /* __ELIBC_ALLTYPES_H */
