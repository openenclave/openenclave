#ifndef _ENCIDL_TYPEINFO_U_H
#define _ENCIDL_TYPEINFO_U_H

#include <openenclave/host.h>

#include "types.h"

/*
********************************************************************************
**
** Structure definitions
**
********************************************************************************
*/

struct EmptyStruct
{
};

extern const OE_StructTI EmptyStruct_ti;

struct MyStruct
{
    oe_uint32_t x;
    const void *data;
    oe_size_t size;
    const char *str;
};

extern const OE_StructTI MyStruct_ti;

struct DeepStruct
{
    struct MyStruct *flat;
    struct MyStruct mine[3];
};

extern const OE_StructTI DeepStruct_ti;

struct MyObject
{
    oe_uint32_t id;
    const char *name;
};

extern const OE_StructTI MyObject_ti;

struct EmbeddedMyObject
{
    struct MyObject object1[1];
    struct MyObject object4[4];
    struct MyObject *object;
    struct MyObject object0[];
};

extern const OE_StructTI EmbeddedMyObject_ti;

struct ListElem
{
    struct ListElem *prev;
    struct ListElem *next;
    const char *name;
};

extern const OE_StructTI ListElem_ti;

struct Object
{
    oe_size_t id;
    char *name;
};

extern const OE_StructTI Object_ti;

struct Embedded
{
    oe_uint32_t xxx;
    oe_uint32_t yyy;
    char str[16];
    char cstr[16];
    wchar_t wstr[16];
    struct Object *objects;
    oe_size_t nobjects;
};

extern const OE_StructTI Embedded_ti;

struct Container
{
    struct Object *object;
    oe_size_t size;
    oe_bool b;
    struct Embedded e;
    struct Embedded ae[2];
    oe_uint32_t *arrData;
    oe_size_t arrSize;
    struct DefinedStruct definedStruct;
    struct UndefinedStruct *undefinedStruct;
    const void *varr;
    oe_size_t sizevarr;
};

extern const OE_StructTI Container_ti;

struct AllTypes
{
    oe_int8_t s8;
    oe_uint8_t u8;
    oe_int16_t s16;
    oe_uint16_t u16;
    oe_int32_t s32;
    oe_uint32_t u32;
    oe_int64_t s64;
    oe_uint64_t u64;
    float r32;
    double r64;
    oe_uint8_t by;
    oe_bool b;
    char c;
    wchar_t w;
    oe_size_t s;
    oe_ssize_t ss;
    char *str;
    oe_size_t strn;
    wchar_t *wcs;
    char stra[32];
    wchar_t wcsa[32];
    struct Object obj1;
    struct Object *obj2;
    oe_uint32_t *data;
    oe_size_t size;
};

extern const OE_StructTI AllTypes_ti;

struct NewTypes
{
    char s8;
    oe_uint8_t u8;
    short s16;
    oe_uint16_t u16;
    int s32;
    unsigned int u32;
    oe_int64_t s64;
    oe_uint64_t u64;
    float r32;
    double r64;
    oe_int64_t ss;
    oe_uint64_t s;
    signed long sl;
    unsigned int ui;
    unsigned long ul;
    unsigned short *usp;
    unsigned char uc;
};

extern const OE_StructTI NewTypes_ti;

struct MyFunctionArgs
{
    const char *cstr;
    char *str;
    oe_size_t nstr;
    oe_uint32_t *u32;
    oe_uint32_t u32a[4];
    char stra[32];
    struct Object obj;
    struct Object *objp;
    struct Object *objr;
};

extern const OE_StructTI MyFunctionArgs_ti;

/*
********************************************************************************
**
** Inbound calls
**
********************************************************************************
*/

OE_EXTERNC oe_int32_t UCopy(
    char *p,
    oe_size_t m,
    const char *q,
    oe_size_t n,
    struct Object **object);

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

OE_EXTERNC OE_Result TCopy(
    OE_Enclave* enclave,
    oe_int32_t *ret,
    char *p,
    oe_size_t m,
    const char *q,
    oe_size_t n,
    struct Object **object);

#endif /* _ENCIDL_TYPEINFO_U_H */
