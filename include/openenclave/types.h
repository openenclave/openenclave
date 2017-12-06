#ifndef _OE_TYPES_H
#define _OE_TYPES_H

#include "defs.h"

/*
**==============================================================================
**
** EAFI_MAX_PATH
**
**==============================================================================
*/

#if defined(MAX_PATH)
# define OE_MAX_PATH MAX_PATH
#elif defined(PATH_MAX)
# define OE_MAX_PATH PATH_MAX
#else
# define OE_MAX_PATH 1024
#endif

/*
**==============================================================================
**
** Printf format specifiers
**
**==============================================================================
*/

/*
**==============================================================================
**
** Basic types:
**
**==============================================================================
*/

#ifdef __GNUC__

typedef long ssize_t;
typedef unsigned long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long ptrdiff_t;

#define OE_INT64_F "%ld"
#define OE_UINT64_F "%lu"

#elif _MSC_VER

typedef long long ssize_t;
typedef unsigned long long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long long uintptr_t;
typedef long long ptrdiff_t;

#define OE_INT64_F "%I64d"
#define OE_UINT64_F "%I64u"

#else
# error unknown compiler - please adapt basic types
#endif


/* Some basic verifications */
OE_STATIC_ASSERT(sizeof(void*) == 8);
OE_STATIC_ASSERT(sizeof(ssize_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(size_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(int16_t) == 2);
OE_STATIC_ASSERT(sizeof(uint16_t) == 2);
OE_STATIC_ASSERT(sizeof(int32_t) == 4);
OE_STATIC_ASSERT(sizeof(int32_t) == 4);
OE_STATIC_ASSERT(sizeof(int64_t) == 8);
OE_STATIC_ASSERT(sizeof(uint64_t) == 8);
OE_STATIC_ASSERT(sizeof(uintptr_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(ptrdiff_t) == sizeof(void*));

#ifndef __cplusplus
# define true 1
# define false 0
# define bool _Bool
#endif

/*
**==============================================================================
**
** OE_Type
**
**==============================================================================
*/

typedef enum _OE_TYPE
{
    OE_NONE_T,
    OE_CHAR_T,
    OE_UCHAR_T,
    OE_WCHAR_T,
    OE_SHORT_T,
    OE_INT_T,
    OE_LONG_T,
    OE_USHORT_T,
    OE_UINT_T,
    OE_ULONG_T,
    OE_BOOL_T,
    OE_INT8_T,
    OE_UINT8_T,
    OE_INT16_T,
    OE_UINT16_T,
    OE_INT32_T,
    OE_UINT32_T,
    OE_INT64_T,
    OE_UINT64_T,
    OE_FLOAT_T,
    OE_DOUBLE_T,
    OE_SIZE_T,
    OE_SSIZE_T,
    OE_STRUCT_T,
    OE_VOID_T,
}
OE_Type;

/*
**==============================================================================
**
** OE_HI_WORD()
** OE_LO_WORD()
** OE_MAKE_WORD()
**
**==============================================================================
*/

#define OE_HI_WORD(X) ((uint64_t)(X >> 32))

#define OE_LO_WORD(X) ((uint64_t)X & 0x00000000FFFFFFFF)

#define OE_MAKE_WORD(HI, LO) (((uint64_t)HI << 32) | (uint64_t)LO)

/*
**==============================================================================
**
** Signature of allocation and deallocation functions.
**
**==============================================================================
*/

typedef void* (*OE_AllocProc)(size_t size);

typedef void (*OE_DeallocProc)(void* ptr);

/*
**==============================================================================
**
** OE_Page
**
**==============================================================================
*/

#define OE_PAGE_SIZE 4096

typedef OE_ALIGNED(OE_PAGE_SIZE) struct _OE_Page
{
    unsigned char data[OE_PAGE_SIZE];
}
OE_Page;

OE_STATIC_ASSERT(__alignof(OE_Page) == OE_PAGE_SIZE);

/*
**==============================================================================
**
** OE_va_list:
**
**==============================================================================
*/

#define OE_va_list __builtin_va_list
#define OE_va_start __builtin_va_start
#define OE_va_arg __builtin_va_arg
#define OE_va_end __builtin_va_end
#define OE_va_copy __builtin_va_copy

#endif /* _OE_TYPES_H */
