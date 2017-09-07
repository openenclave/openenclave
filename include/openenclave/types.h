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
** OE_COUNTOF()
** OE_OFFSETOF()
**
**==============================================================================
*/

#define OE_COUNTOF(ARR) (sizeof(ARR) / sizeof(ARR[0]))

#define OE_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)

/*
**==============================================================================
**
** Printf format specifiers
**
**==============================================================================
*/

#define OE_INT64_F "%ld"
#define OE_UINT64_F "%lu"

/*
**==============================================================================
**
** Basic types:
**
**==============================================================================
*/

#ifndef __cplusplus
typedef int wchar_t;
#endif

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

#ifdef __cplusplus
# define true true
#else
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

typedef struct _OE_Page
{
    unsigned char data[OE_PAGE_SIZE];
}
OE_Page
OE_ALIGNED(OE_PAGE_SIZE);

#endif /* _OE_TYPES_H */
