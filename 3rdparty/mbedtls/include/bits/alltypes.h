#ifndef _OE_MBEDTLS_ALLTYPES_H
#define _OE_MBEDTLS_ALLTYPES_H

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#define CHAR_BIT 8

#ifndef NULL
#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif
#endif

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef long time_t;
typedef __builtin_va_list va_list;
typedef long suseconds_t;
typedef int clockid_t;

#endif /* _OE_MBEDTLS_ALLTYPES_H */
