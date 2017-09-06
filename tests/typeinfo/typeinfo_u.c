#include <openenclave/host.h>
#include "typeinfo_u.h"
#include "types.h"

OE_INLINE void* _ConstMemcpy(
    const void* dest, 
    const void* src,
    oe_size_t n)
{
    return memcpy((void*)dest, src, n);
}


/*
********************************************************************************
**
** Type Information
**
********************************************************************************
*/

extern const OE_StructTI EmptyStruct_ti;

static const OE_FieldTI _EmptyStruct_fields_ti[] =
{
};

const OE_StructTI EmptyStruct_ti =
{
    0, /* flags */
    "EmptyStruct", /* name */
    sizeof(struct EmptyStruct), /* size */
    _EmptyStruct_fields_ti, /* fields */
    OE_COUNTOF(_EmptyStruct_fields_ti) /* nfields */
};

extern const OE_StructTI MyStruct_ti;

static const OE_FieldTI _MyStruct_fields_ti[] =
{
    {
        0, /* flags */
        "x", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyStruct, x),
        sizeof(oe_uint32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "data", /* name */
        OE_VOID_T, /* type */
        OE_NULL, /* structTI */
        "size", /* countField */
        OE_OFFSETOF(struct MyStruct, data),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "size", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyStruct, size),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "str", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyStruct, str),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI MyStruct_ti =
{
    0, /* flags */
    "MyStruct", /* name */
    sizeof(struct MyStruct), /* size */
    _MyStruct_fields_ti, /* fields */
    OE_COUNTOF(_MyStruct_fields_ti) /* nfields */
};

extern const OE_StructTI DeepStruct_ti;

static const OE_FieldTI _DeepStruct_fields_ti[] =
{
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "flat", /* name */
        OE_STRUCT_T, /* type */
        &MyStruct_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct DeepStruct, flat),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_ARRAY, /* flags */
        "mine", /* name */
        OE_STRUCT_T, /* type */
        &MyStruct_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct DeepStruct, mine),
        sizeof(struct MyStruct) * 3, /* size */
        3, /* subscript */
    },
};

const OE_StructTI DeepStruct_ti =
{
    0, /* flags */
    "DeepStruct", /* name */
    sizeof(struct DeepStruct), /* size */
    _DeepStruct_fields_ti, /* fields */
    OE_COUNTOF(_DeepStruct_fields_ti) /* nfields */
};

extern const OE_StructTI MyObject_ti;

static const OE_FieldTI _MyObject_fields_ti[] =
{
    {
        0, /* flags */
        "id", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyObject, id),
        sizeof(oe_uint32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "name", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyObject, name),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI MyObject_ti =
{
    0, /* flags */
    "MyObject", /* name */
    sizeof(struct MyObject), /* size */
    _MyObject_fields_ti, /* fields */
    OE_COUNTOF(_MyObject_fields_ti) /* nfields */
};

extern const OE_StructTI EmbeddedMyObject_ti;

static const OE_FieldTI _EmbeddedMyObject_fields_ti[] =
{
    {
        OE_FLAG_ARRAY, /* flags */
        "object1", /* name */
        OE_STRUCT_T, /* type */
        &MyObject_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct EmbeddedMyObject, object1),
        sizeof(struct MyObject) * 1, /* size */
        1, /* subscript */
    },
    {
        OE_FLAG_ARRAY, /* flags */
        "object4", /* name */
        OE_STRUCT_T, /* type */
        &MyObject_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct EmbeddedMyObject, object4),
        sizeof(struct MyObject) * 4, /* size */
        4, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "object", /* name */
        OE_STRUCT_T, /* type */
        &MyObject_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct EmbeddedMyObject, object),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_ARRAY, /* flags */
        "object0", /* name */
        OE_STRUCT_T, /* type */
        &MyObject_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct EmbeddedMyObject, object0),
        sizeof(struct MyObject) * 0, /* size */
        0, /* subscript */
    },
};

const OE_StructTI EmbeddedMyObject_ti =
{
    0, /* flags */
    "EmbeddedMyObject", /* name */
    sizeof(struct EmbeddedMyObject), /* size */
    _EmbeddedMyObject_fields_ti, /* fields */
    OE_COUNTOF(_EmbeddedMyObject_fields_ti) /* nfields */
};

extern const OE_StructTI ListElem_ti;

static const OE_FieldTI _ListElem_fields_ti[] =
{
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "prev", /* name */
        OE_STRUCT_T, /* type */
        &ListElem_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct ListElem, prev),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "next", /* name */
        OE_STRUCT_T, /* type */
        &ListElem_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct ListElem, next),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "name", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct ListElem, name),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ListElem_ti =
{
    0, /* flags */
    "ListElem", /* name */
    sizeof(struct ListElem), /* size */
    _ListElem_fields_ti, /* fields */
    OE_COUNTOF(_ListElem_fields_ti) /* nfields */
};

extern const OE_StructTI Object_ti;

static const OE_FieldTI _Object_fields_ti[] =
{
    {
        0, /* flags */
        "id", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Object, id),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "name", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Object, name),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI Object_ti =
{
    0, /* flags */
    "Object", /* name */
    sizeof(struct Object), /* size */
    _Object_fields_ti, /* fields */
    OE_COUNTOF(_Object_fields_ti) /* nfields */
};

extern const OE_StructTI Embedded_ti;

static const OE_FieldTI _Embedded_fields_ti[] =
{
    {
        0, /* flags */
        "xxx", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Embedded, xxx),
        sizeof(oe_uint32_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "yyy", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Embedded, yyy),
        sizeof(oe_uint32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_ARRAY, /* flags */
        "str", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Embedded, str),
        sizeof(char) * 16, /* size */
        16, /* subscript */
    },
    {
        OE_FLAG_ARRAY|OE_FLAG_STRING, /* flags */
        "cstr", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Embedded, cstr),
        sizeof(char) * 16, /* size */
        16, /* subscript */
    },
    {
        OE_FLAG_ARRAY|OE_FLAG_STRING, /* flags */
        "wstr", /* name */
        OE_WCHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Embedded, wstr),
        sizeof(wchar_t) * 16, /* size */
        16, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objects", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "nobjects", /* countField */
        OE_OFFSETOF(struct Embedded, objects),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "nobjects", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Embedded, nobjects),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI Embedded_ti =
{
    0, /* flags */
    "Embedded", /* name */
    sizeof(struct Embedded), /* size */
    _Embedded_fields_ti, /* fields */
    OE_COUNTOF(_Embedded_fields_ti) /* nfields */
};

extern const OE_StructTI Container_ti;

static const OE_FieldTI _Container_fields_ti[] =
{
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "object", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "size", /* countField */
        OE_OFFSETOF(struct Container, object),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "size", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, size),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "b", /* name */
        OE_BOOL_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, b),
        sizeof(oe_bool), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "e", /* name */
        OE_STRUCT_T, /* type */
        &Embedded_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, e),
        sizeof(struct Embedded), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_ARRAY, /* flags */
        "ae", /* name */
        OE_STRUCT_T, /* type */
        &Embedded_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, ae),
        sizeof(struct Embedded) * 2, /* size */
        2, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "arrData", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        "arrSize", /* countField */
        OE_OFFSETOF(struct Container, arrData),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "arrSize", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, arrSize),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_UNCHECKED, /* flags */
        "definedStruct", /* name */
        OE_STRUCT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, definedStruct),
        sizeof(struct DefinedStruct), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "undefinedStruct", /* name */
        OE_STRUCT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, undefinedStruct),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "varr", /* name */
        OE_VOID_T, /* type */
        OE_NULL, /* structTI */
        "sizevarr", /* countField */
        OE_OFFSETOF(struct Container, varr),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "sizevarr", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct Container, sizevarr),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI Container_ti =
{
    0, /* flags */
    "Container", /* name */
    sizeof(struct Container), /* size */
    _Container_fields_ti, /* fields */
    OE_COUNTOF(_Container_fields_ti) /* nfields */
};

extern const OE_StructTI AllTypes_ti;

static const OE_FieldTI _AllTypes_fields_ti[] =
{
    {
        0, /* flags */
        "s8", /* name */
        OE_INT8_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, s8),
        sizeof(oe_int8_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u8", /* name */
        OE_UINT8_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, u8),
        sizeof(oe_uint8_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s16", /* name */
        OE_INT16_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, s16),
        sizeof(oe_int16_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u16", /* name */
        OE_UINT16_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, u16),
        sizeof(oe_uint16_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s32", /* name */
        OE_INT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, s32),
        sizeof(oe_int32_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u32", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, u32),
        sizeof(oe_uint32_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s64", /* name */
        OE_INT64_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, s64),
        sizeof(oe_int64_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u64", /* name */
        OE_UINT64_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, u64),
        sizeof(oe_uint64_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "r32", /* name */
        OE_FLOAT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, r32),
        sizeof(float), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "r64", /* name */
        OE_DOUBLE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, r64),
        sizeof(double), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "by", /* name */
        OE_UINT8_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, by),
        sizeof(oe_uint8_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "b", /* name */
        OE_BOOL_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, b),
        sizeof(oe_bool), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "c", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, c),
        sizeof(char), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "w", /* name */
        OE_WCHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, w),
        sizeof(wchar_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, s),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "ss", /* name */
        OE_SSIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, ss),
        sizeof(oe_ssize_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_STRING, /* flags */
        "str", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        "strn", /* countField */
        OE_OFFSETOF(struct AllTypes, str),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "strn", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, strn),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "wcs", /* name */
        OE_WCHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, wcs),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_ARRAY|OE_FLAG_STRING, /* flags */
        "stra", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, stra),
        sizeof(char) * 32, /* size */
        32, /* subscript */
    },
    {
        OE_FLAG_ARRAY|OE_FLAG_STRING, /* flags */
        "wcsa", /* name */
        OE_WCHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, wcsa),
        sizeof(wchar_t) * 32, /* size */
        32, /* subscript */
    },
    {
        0, /* flags */
        "obj1", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, obj1),
        sizeof(struct Object), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "obj2", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct AllTypes, obj2),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "data", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        "size", /* countField */
        OE_OFFSETOF(struct AllTypes, data),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "size", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct AllTypes, size),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI AllTypes_ti =
{
    0, /* flags */
    "AllTypes", /* name */
    sizeof(struct AllTypes), /* size */
    _AllTypes_fields_ti, /* fields */
    OE_COUNTOF(_AllTypes_fields_ti) /* nfields */
};

extern const OE_StructTI NewTypes_ti;

static const OE_FieldTI _NewTypes_fields_ti[] =
{
    {
        0, /* flags */
        "s8", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, s8),
        sizeof(char), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u8", /* name */
        OE_UINT8_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, u8),
        sizeof(oe_uint8_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s16", /* name */
        OE_SHORT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, s16),
        sizeof(short), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u16", /* name */
        OE_UINT16_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, u16),
        sizeof(oe_uint16_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s32", /* name */
        OE_INT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, s32),
        sizeof(int), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u32", /* name */
        OE_UINT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, u32),
        sizeof(unsigned int), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s64", /* name */
        OE_INT64_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, s64),
        sizeof(oe_int64_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "u64", /* name */
        OE_UINT64_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, u64),
        sizeof(oe_uint64_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "r32", /* name */
        OE_FLOAT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, r32),
        sizeof(float), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "r64", /* name */
        OE_DOUBLE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, r64),
        sizeof(double), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "ss", /* name */
        OE_INT64_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, ss),
        sizeof(oe_int64_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "s", /* name */
        OE_UINT64_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, s),
        sizeof(oe_uint64_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "sl", /* name */
        OE_ULONG_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, sl),
        sizeof(signed long), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "ui", /* name */
        OE_UINT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, ui),
        sizeof(unsigned int), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "ul", /* name */
        OE_ULONG_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, ul),
        sizeof(unsigned long), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "usp", /* name */
        OE_USHORT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, usp),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "uc", /* name */
        OE_UCHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct NewTypes, uc),
        sizeof(unsigned char), /* size */
        0, /* subscript */
    },
};

const OE_StructTI NewTypes_ti =
{
    0, /* flags */
    "NewTypes", /* name */
    sizeof(struct NewTypes), /* size */
    _NewTypes_fields_ti, /* fields */
    OE_COUNTOF(_NewTypes_fields_ti) /* nfields */
};

extern const OE_StructTI MyFunctionArgs_ti;

static const OE_FieldTI _MyFunctionArgs_fields_ti[] =
{
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "cstr", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, cstr),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_STRING, /* flags */
        "str", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        "nstr", /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, str),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "nstr", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, nstr),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "u32", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, u32),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_ARRAY, /* flags */
        "u32a", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, u32a),
        sizeof(oe_uint32_t) * 4, /* size */
        4, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_ARRAY|OE_FLAG_STRING, /* flags */
        "stra", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, stra),
        sizeof(char) * 32, /* size */
        32, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "obj", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        OE_NULL, /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, obj),
        sizeof(struct Object), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objp", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, objp),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objr", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct MyFunctionArgs, objr),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI MyFunctionArgs_ti =
{
    0, /* flags */
    "MyFunctionArgs", /* name */
    sizeof(struct MyFunctionArgs), /* size */
    _MyFunctionArgs_fields_ti, /* fields */
    OE_COUNTOF(_MyFunctionArgs_fields_ti) /* nfields */
};

struct UCopyArgs
{
    oe_int32_t ret;
    unsigned char __pad1[4];
    char *p;
    unsigned char __pad2[4];
    oe_size_t m;
    unsigned char __pad3[4];
    const char *q;
    unsigned char __pad4[4];
    oe_size_t n;
    unsigned char __pad5[4];
    struct Object *object;
    unsigned char __pad6[4];
};

extern const OE_StructTI UCopyArgs_ti;

static const OE_FieldTI _UCopyArgs_fields_ti[] =
{
    {
        OE_FLAG_OCALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct UCopyArgs, ret),
        sizeof(oe_int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "p", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        "m", /* countParam */
        OE_OFFSETOF(struct UCopyArgs, p),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "m", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct UCopyArgs, m),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "q", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        "n", /* countParam */
        OE_OFFSETOF(struct UCopyArgs, q),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "n", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct UCopyArgs, n),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_REF|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "object", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct UCopyArgs, object),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI UCopyArgs_ti =
{
    0, /* flags */
    "UCopy", /* name */
    sizeof(struct UCopyArgs), /* size */
    _UCopyArgs_fields_ti, /* params */
    OE_COUNTOF(_UCopyArgs_fields_ti) /* nparams */
};

struct TCopyArgs
{
    oe_int32_t ret;
    unsigned char __pad1[4];
    char *p;
    unsigned char __pad2[4];
    oe_size_t m;
    unsigned char __pad3[4];
    const char *q;
    unsigned char __pad4[4];
    oe_size_t n;
    unsigned char __pad5[4];
    struct Object *object;
    unsigned char __pad6[4];
};

extern const OE_StructTI TCopyArgs_ti;

static const OE_FieldTI _TCopyArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct TCopyArgs, ret),
        sizeof(oe_int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "p", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        "m", /* countParam */
        OE_OFFSETOF(struct TCopyArgs, p),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "m", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct TCopyArgs, m),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "q", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        "n", /* countParam */
        OE_OFFSETOF(struct TCopyArgs, q),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "n", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct TCopyArgs, n),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_REF|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "object", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct TCopyArgs, object),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TCopyArgs_ti =
{
    0, /* flags */
    "TCopy", /* name */
    sizeof(struct TCopyArgs), /* size */
    _TCopyArgs_fields_ti, /* params */
    OE_COUNTOF(_TCopyArgs_fields_ti) /* nparams */
};

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

/* ICALL: generator.cpp(657) */
OE_OCALL void __UCopy(void* args)
{
    struct UCopyArgs* __a = (struct UCopyArgs*)args;

    __a->ret = UCopy(
        __a->p,
        __a->m,
        __a->q,
        __a->n,
        &__a->object);
}

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TCopy(
    OE_Enclave* enclave,
    oe_int32_t *ret,
    char *p,
    oe_size_t m,
    const char *q,
    oe_size_t n,
    struct Object **object)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TCopyArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.p = p;
    __args.m = m;
    __args.q = q;
    __args.n = n;
    __args.object = (void*)object;


    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TCopy", &__args);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    if (ret)
        *ret = __args.ret;

    /*************************/
    /*** output parameters ***/
    /*************************/

    if (object)
        *object = __args.object;

done:
    return __r;
}

