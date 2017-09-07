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
    uint32_t x;
    const void *data;
    size_t size;
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
    uint32_t id;
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
    size_t id;
    char *name;
};

extern const OE_StructTI Object_ti;

struct Embedded
{
    uint32_t xxx;
    uint32_t yyy;
    char str[16];
    char cstr[16];
    wchar_t wstr[16];
    struct Object *objects;
    size_t nobjects;
};

extern const OE_StructTI Embedded_ti;

struct Container
{
    struct Object *object;
    size_t size;
    bool b;
    struct Embedded e;
    struct Embedded ae[2];
    uint32_t *arrData;
    size_t arrSize;
    struct DefinedStruct definedStruct;
    struct UndefinedStruct *undefinedStruct;
    const void *varr;
    size_t sizevarr;
};

extern const OE_StructTI Container_ti;

struct AllTypes
{
    int8_t s8;
    uint8_t u8;
    int16_t s16;
    uint16_t u16;
    int32_t s32;
    uint32_t u32;
    int64_t s64;
    uint64_t u64;
    float r32;
    double r64;
    uint8_t by;
    bool b;
    char c;
    wchar_t w;
    size_t s;
    ssize_t ss;
    char *str;
    size_t strn;
    wchar_t *wcs;
    char stra[32];
    wchar_t wcsa[32];
    struct Object obj1;
    struct Object *obj2;
    uint32_t *data;
    size_t size;
};

extern const OE_StructTI AllTypes_ti;

struct NewTypes
{
    char s8;
    uint8_t u8;
    short s16;
    uint16_t u16;
    int s32;
    unsigned int u32;
    int64_t s64;
    uint64_t u64;
    float r32;
    double r64;
    int64_t ss;
    uint64_t s;
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
    size_t nstr;
    uint32_t *u32;
    uint32_t u32a[4];
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

OE_EXTERNC int32_t UCopy(
    char *p,
    size_t m,
    const char *q,
    size_t n,
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
    int32_t *ret,
    char *p,
    size_t m,
    const char *q,
    size_t n,
    struct Object **object);

#endif /* _ENCIDL_TYPEINFO_U_H */
