// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 0
#include <ctype.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/typeinfo.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
**==============================================================================
**
** Utility functions:
**
**==============================================================================
*/

static void* _Calloc(size_t n, void*(alloc)(size_t size))
{
    void* p;

    if (!(p = alloc(n)))
        return NULL;

    return memset(p, 0, n);
}

static char* _Strdup(const char* s, size_t n, void*(alloc)(size_t size))
{
    char* p;

    if (!s || (alloc == NULL))
        return NULL;

    if (n == 0)
        n = strlen(s) + 1;

    if (!(p = (char*)alloc(n * sizeof(char))))
        return NULL;

    memset(p, 0, n * sizeof(char));
    return memcpy(p, s, n * sizeof(char));
}

static size_t _SizeofStr(const char* s)
{
    if (!s)
        return 0;

    return (strlen(s) + 1) * sizeof(char);
}

static oe_result_t _StrToSize(const char* str, size_t* size)
{
    size_t r = 1;
    size_t x = 0;
    size_t n = 0;
    const char* p = str;

    if (!size)
        return OE_INVALID_PARAMETER;

    while (*p)
        p++;

    while (p != str)
    {
        char c = *--p;

        if (!(c >= '0' && c <= '9'))
            return OE_FAILURE;

        x += r * (c - '0');
        r *= 10;

        /* Check for overflow */
        if (x < n)
            return OE_FAILURE;

        n = x;
    }

    *size = x;

    return OE_OK;
}

static const oe_field_ti_t* _FindFieldTI(
    const oe_struct_ti_t* ti,
    const char* name)
{
    size_t i;

    for (i = 0; i < ti->nfields; i++)
    {
        const oe_field_ti_t* fti = &ti->fields[i];

        if (strcmp(fti->name, name) == 0)
            return fti;
    }

    return NULL;
}

static oe_result_t _GetCount(
    const oe_struct_ti_t* ti,
    const void* structIn,
    const oe_field_ti_t* fti,
    size_t* count)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_field_ti_t* cfti;

    if (count)
        *count = 0;

    /* Check for null parameters */
    if (!ti || !fti || !structIn || !count)
        OE_THROW(OE_INVALID_PARAMETER);

    /* If no [count] qualifier */
    if (!(fti->flags & OE_FLAG_COUNT))
        OE_THROW(OE_OK);

    /* If count field is empty */
    if (!fti->countField)
        OE_THROW(OE_UNEXPECTED);

    /* If count field is already an unsigned integer */
    if (_StrToSize(fti->countField, count) == OE_OK)
        OE_THROW(OE_OK);

    /* Find the count field */
    if (!(cfti = _FindFieldTI(ti, fti->countField)))
        OE_THROW(OE_NOT_FOUND);

    /* Check type of count field (size_t) */
    if (cfti->type != OE_SIZE_T)
        OE_THROW(OE_PUBLIC_KEY_NOT_FOUND);

    /* Read the count field from the structure */
    *count = *(const size_t*)((const uint8_t*)structIn + cfti->offset);

    result = OE_OK;

OE_CATCH:
    return result;
}

/* Get the size of the given type */
static size_t _GetTypeSizeFromType(oe_type_t type)
{
    switch (type)
    {
        case OE_NONE_T:
            return 0;
        case OE_CHAR_T:
            return sizeof(char);
        case OE_SHORT_T:
            return sizeof(short);
        case OE_INT_T:
            return sizeof(int);
        case OE_USHORT_T:
            return sizeof(unsigned short);
        case OE_UINT_T:
            return sizeof(unsigned int);
        case OE_BOOL_T:
            return sizeof(bool);
        case OE_INT8_T:
            return sizeof(int8_t);
        case OE_UCHAR_T:
        case OE_UINT8_T:
            return sizeof(uint8_t);
        case OE_INT16_T:
            return sizeof(int16_t);
        case OE_UINT16_T:
            return sizeof(uint16_t);
        case OE_INT32_T:
            return sizeof(int32_t);
        case OE_UINT32_T:
            return sizeof(uint32_t);
        case OE_INT64_T:
            return sizeof(int64_t);
        case OE_UINT64_T:
            return sizeof(uint64_t);
        case OE_FLOAT_T:
            return sizeof(float);
        case OE_DOUBLE_T:
            return sizeof(double);
        case OE_SIZE_T:
            return sizeof(size_t);
        case OE_SSIZE_T:
            return sizeof(ssize_t);
        case OE_STRUCT_T:
            return 0;
        case OE_VOID_T:
            return 1;
        case OE_LONG_T:
        case OE_ULONG_T:
        case OE_WCHAR_T:
        case __OE_TYPE_MAX:
        {
            /* Unsupported types */
            return 0;
        }
    }

    return 0;
}

/* Get type-size of this field (not necessarily the same as field size) */
static size_t _GetTypeSize(const oe_field_ti_t* fti)
{
    if (fti->type == OE_STRUCT_T)
        return fti->sti->size;

    return _GetTypeSizeFromType(fti->type);
}

/*
**==============================================================================
**
** Equality functions:
**
**==============================================================================
*/

static bool _ScalarEq(oe_type_t type, const void* p1, const void* p2)
{
    switch (type)
    {
        case OE_NONE_T:
            return false;
        case OE_CHAR_T:
            return *((char*)p1) == *((char*)p2);
        case OE_SHORT_T:
            return *((short*)p1) == *((short*)p2);
        case OE_INT_T:
            return *((int*)p1) == *((int*)p2);
        case OE_USHORT_T:
            return *((unsigned short*)p1) == *((unsigned short*)p2);
        case OE_UINT_T:
            return *((unsigned int*)p1) == *((unsigned int*)p2);
        case OE_BOOL_T:
            return *((bool*)p1) == *((bool*)p2);
        case OE_INT8_T:
            return *((int8_t*)p1) == *((int8_t*)p2);
        case OE_UCHAR_T:
        case OE_UINT8_T:
            return *((uint8_t*)p1) == *((uint8_t*)p2);
        case OE_INT16_T:
            return *((int16_t*)p1) == *((int16_t*)p2);
        case OE_UINT16_T:
            return *((uint16_t*)p1) == *((uint16_t*)p2);
        case OE_INT32_T:
            return *((int32_t*)p1) == *((int32_t*)p2);
        case OE_UINT32_T:
            return *((uint32_t*)p1) == *((uint32_t*)p2);
        case OE_INT64_T:
            return *((int64_t*)p1) == *((int64_t*)p2);
        case OE_UINT64_T:
            return *((uint64_t*)p1) == *((uint64_t*)p2);
        case OE_FLOAT_T:
            return *((float*)p1) == *((float*)p2);
        case OE_DOUBLE_T:
            return *((double*)p1) == *((double*)p2);
        case OE_SIZE_T:
            return *((size_t*)p1) == *((size_t*)p2);
        case OE_SSIZE_T:
            return *((ssize_t*)p1) == *((ssize_t*)p2);
        case OE_STRUCT_T:
            return false;
        case OE_VOID_T:
            return false;
        case OE_LONG_T:
        case OE_ULONG_T:
        case OE_WCHAR_T:
        case __OE_TYPE_MAX:
        {
            /* Unsupported types */
            return false;
        }
    }

    /* Unreachable */
    return false;
}

static bool _Real32Eq(const float* p1, const float* p2, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (p1[i] != p2[i])
            return false;

    return true;
}

static bool _Real64Eq(const double* p1, const double* p2, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (p1[i] != p2[i])
            return false;

    return true;
}

static bool _BytesEq(const void* p1, const void* p2, size_t n)
{
    return memcmp(p1, p2, n) == 0 ? true : false;
}

static bool _ArrayEq(oe_type_t type, const void* p1, const void* p2, size_t n)
{
    switch (type)
    {
        case OE_NONE_T:
            return false;
        case OE_CHAR_T:
            return _BytesEq(p1, p2, sizeof(char) * n);
        case OE_BOOL_T:
            return _BytesEq(p1, p2, sizeof(bool) * n);
        case OE_INT8_T:
            return _BytesEq(p1, p2, sizeof(int8_t) * n);
        case OE_UCHAR_T:
        case OE_UINT8_T:
            return _BytesEq(p1, p2, sizeof(uint8_t) * n);
        case OE_SHORT_T:
        case OE_INT16_T:
            return _BytesEq(p1, p2, sizeof(int16_t) * n);
        case OE_USHORT_T:
        case OE_UINT16_T:
            return _BytesEq(p1, p2, sizeof(uint16_t) * n);
        case OE_INT_T:
        case OE_INT32_T:
            return _BytesEq(p1, p2, sizeof(int32_t) * n);
        case OE_UINT_T:
        case OE_UINT32_T:
            return _BytesEq(p1, p2, sizeof(uint32_t) * n);
        case OE_INT64_T:
            return _BytesEq(p1, p2, sizeof(int64_t) * n);
        case OE_UINT64_T:
            return _BytesEq(p1, p2, sizeof(uint64_t) * n);
        case OE_FLOAT_T:
            return _Real32Eq(p1, p2, sizeof(float) * n);
        case OE_DOUBLE_T:
            return _Real64Eq(p1, p2, sizeof(double) * n);
        case OE_SIZE_T:
            return _BytesEq(p1, p2, sizeof(size_t) * n);
        case OE_SSIZE_T:
            return _BytesEq(p1, p2, sizeof(ssize_t) * n);
        case OE_STRUCT_T:
            return false;
        case OE_VOID_T:
            return false;
        case OE_LONG_T:
        case OE_ULONG_T:
        case OE_WCHAR_T:
        case __OE_TYPE_MAX:
        {
            /* Unsupported types */
            return false;
        }
    }

    /* Unreachable */
    return false;
}

static oe_result_t _StructsEq(
    const oe_struct_ti_t* sti,
    const void* s1,
    const void* s2,
    size_t count,
    bool* flag)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    if (flag)
        *flag = false;

    if (!sti || !s1 || !s2 || !flag)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < count; i++)
    {
        bool tmp;
        OE_TRY(oe_struct_eq(sti, s1, s2, &tmp));
        if (!tmp)
            OE_THROW(OE_OK);
    }

    *flag = true;
    result = OE_OK;

OE_CATCH:
    return result;
}

static oe_result_t _FieldEq(
    const oe_struct_ti_t* sti,
    const void* s1,
    const void* s2,
    size_t index,
    bool* flag)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_field_ti_t* fti;
    size_t count1 = 0;
    size_t count2 = 0;
    const uint8_t* f1;
    const uint8_t* f2;

    if (flag)
        *flag = false;

    if (!sti || !s1 || !s2 || !flag)
        OE_THROW(OE_INVALID_PARAMETER);

    if (index >= sti->nfields)
        OE_THROW(OE_OUT_OF_BOUNDS);

    fti = &sti->fields[index];

    OE_TRACE_INFO("_FieldEq(): %s.%s\n", sti->name, fti->name);

    if (fti->flags & OE_FLAG_COUNT)
    {
        OE_TRY(_GetCount(sti, s1, fti, &count1));
        OE_TRY(_GetCount(sti, s2, fti, &count2));
    }

    if (count1 != count2)
        OE_THROW(OE_OK);

    f1 = (const uint8_t*)s1 + fti->offset;
    f2 = (const uint8_t*)s2 + fti->offset;

    if (fti->flags & OE_FLAG_PTR)
    {
        const void* p1 = *(const void**)f1;
        const void* p2 = *(const void**)f2;

        if (!p1 || !p2)
        {
            if (p1)
                OE_THROW(OE_OK);
            if (p2)
                OE_THROW(OE_OK);

            *flag = true;
            OE_THROW(OE_OK);
        }

        if (fti->flags & OE_FLAG_STRING)
        {
            if (fti->type == OE_CHAR_T)
            {
                if (strcmp((const char*)p1, (const char*)p2) != 0)
                    OE_THROW(OE_OK);
            }
            else
            {
                OE_THROW(OE_UNEXPECTED);
            }
        }
        else if (fti->type == OE_STRUCT_T)
        {
            bool tmp;

            if (!count1)
                OE_THROW(OE_UNEXPECTED);

            OE_TRY(_StructsEq(fti->sti, p1, p2, count1, &tmp));

            if (!tmp)
                OE_THROW(OE_OK);
        }
        else
        {
            if (!count1)
                OE_THROW(OE_UNEXPECTED);

            if (!_ArrayEq(fti->type, p1, p2, count1))
                OE_THROW(OE_OK);
        }
    }
    else if (fti->flags & OE_FLAG_ARRAY)
    {
        if (fti->flags & OE_FLAG_STRING)
        {
            if (fti->type == OE_CHAR_T)
            {
                if (strcmp((const char*)f1, (const char*)f2) != 0)
                    OE_THROW(OE_OK);
            }
            else
            {
                OE_THROW(OE_UNEXPECTED);
            }
        }
        else if (fti->type == OE_STRUCT_T)
        {
            bool tmp;
            OE_TRY(_StructsEq(fti->sti, f1, f2, fti->subscript, &tmp));
            if (!tmp)
                OE_THROW(OE_OK);
        }
        else
        {
            if (!_ArrayEq(fti->type, f1, f2, fti->subscript))
                OE_THROW(OE_OK);
        }
    }
    else
    {
        if (fti->type == OE_STRUCT_T)
        {
            bool tmp;
            OE_TRY(_StructsEq(fti->sti, f1, f2, 1, &tmp));
            if (!tmp)
                OE_THROW(OE_OK);
        }
        else
        {
            if (!_ScalarEq(fti->type, f1, f2))
                OE_THROW(OE_OK);
        }
    }

    *flag = true;
    result = OE_OK;

OE_CATCH:
    return result;
}

oe_result_t oe_struct_eq(
    const oe_struct_ti_t* sti,
    const void* s1,
    const void* s2,
    bool* flag)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    if (flag)
        *flag = false;

    if (!sti || !s1 || !s2 || !flag)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        bool tmp;
        OE_TRY(_FieldEq(sti, s1, s2, i, &tmp));
        if (!tmp)
            OE_THROW(OE_OK);
    }

    *flag = true;
    result = OE_OK;

OE_CATCH:
    return result;
}

/*
**==============================================================================
**
** Printing functions:
**
**==============================================================================
*/

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
static void _Indent(size_t n)
{
    for (size_t i = 0; i < n; i++)
        OE_PRINTF("    ");
}
#endif

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
OE_PRINTF_FORMAT(2, 3)
static void Iprintf(size_t n, const char* format, ...)
{
    _Indent(n);
    va_list ap;
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
}
#endif

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
#define FUNCTION _PrintStr
#define TYPE char
#define FORMAT "%c"
#define PREFIX ""
#include "printstr.c"
#undef FUNCTION
#undef TYPE
#undef FORMAT
#undef PREFIX
#endif

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
static void _PrintStruct(
    const oe_struct_ti_t* ti,
    const void* structIn,
    size_t depth);
#endif

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
static void _PrintScalar(const oe_field_ti_t* fti, const void* p, size_t depth)
{
    switch (fti->type)
    {
        case OE_NONE_T:
            break;
        case OE_CHAR_T:
            OE_PRINTF("%02X", *(const char*)p);
            break;
        case OE_BOOL_T:
            OE_PRINTF("%s", (*(const bool*)p) ? "true" : "false");
            break;
        case OE_INT8_T:
            OE_PRINTF("%d", *(const int8_t*)p);
            break;
        case OE_UCHAR_T:
        case OE_UINT8_T:
            OE_PRINTF("%u", *(const uint8_t*)p);
            break;
        case OE_SHORT_T:
        case OE_INT16_T:
            OE_PRINTF("%d", *(const int16_t*)p);
            break;
        case OE_USHORT_T:
        case OE_UINT16_T:
            OE_PRINTF("%u", *(const uint16_t*)p);
            break;
        case OE_INT_T:
        case OE_INT32_T:
            OE_PRINTF("%d", *(const int32_t*)p);
            break;
        case OE_UINT_T:
        case OE_UINT32_T:
            OE_PRINTF("%u", *(const uint32_t*)p);
            break;
        case OE_INT64_T:
            OE_PRINTF("%lld", OE_LLD(*(const int64_t*)p));
            break;
        case OE_UINT64_T:
            OE_PRINTF("%llu", OE_LLU(*(const uint64_t*)p));
            break;
        case OE_FLOAT_T:
            OE_PRINTF("%f", *(const float*)p);
            break;
        case OE_DOUBLE_T:
            OE_PRINTF("%lf", *(const double*)p);
            break;
        case OE_SIZE_T:
            OE_PRINTF("%zu", *(const size_t*)p);
            break;
        case OE_SSIZE_T:
            OE_PRINTF("%zd", *(const ssize_t*)p);
            break;
        case OE_STRUCT_T:
            _PrintStruct(fti->sti, p, depth);
            break;
        case OE_VOID_T:
            OE_PRINTF("%02X", *(const uint8_t*)p);
            break;
        case OE_LONG_T:
        case OE_ULONG_T:
        case OE_WCHAR_T:
        case __OE_TYPE_MAX:
        {
            /* Unsupported types */
            break;
        }
    }
}
#endif

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
static void _PrintArray(
    const oe_field_ti_t* fti,
    const void* arr,
    size_t elemSize, // elemSize in bytes of one elements:
    size_t arrSize,  // number of total elements:
    size_t depth)
{
    const unsigned char* p = (const unsigned char*)arr;
    bool lineSeparated = false;

    if (fti->flags & OE_FLAG_STRING)
    {
        if (fti->type == OE_CHAR_T)
            _PrintStr((const char*)p, arrSize);
        return;
    }

    if (fti->type == OE_STRUCT_T)
        lineSeparated = true;

    if (lineSeparated)
    {
        OE_PRINTF("\n");
        Iprintf(depth, "{\n");
        depth++;
        _Indent(depth);
    }
    else
        OE_PRINTF("{ ");

    for (size_t i = 0; i < arrSize; i++)
    {
        _PrintScalar(fti, p, depth);

        if (i + 1 != arrSize)
        {
            OE_PRINTF(", ");
            if (lineSeparated)
            {
                OE_PRINTF("\n");
                _Indent(depth);
            }
        }
        else
            OE_PRINTF(" ");

        p += elemSize;
    }

    if (lineSeparated)
    {
        depth--;
        OE_PRINTF("\n");
        Iprintf(depth, "}");
    }
    else
        OE_PRINTF("}");
}
#endif

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
static void _PrintStruct(
    const oe_struct_ti_t* ti,
    const void* structIn,
    size_t depth)
{
    size_t i;

    /* Check for null parameters */
    if (!ti)
        return;

    OE_PRINTF("struct %s\n", ti->name);
    Iprintf(depth, "{\n");
    depth++;

    /* Print each field of this structure */
    for (i = 0; i < ti->nfields; i++)
    {
        const oe_field_ti_t* fti = &ti->fields[i];
        const uint8_t* p = (const uint8_t*)structIn + fti->offset;

        if (fti->flags & OE_FLAG_ARRAY)
            Iprintf(depth, "%s[%u] = ", fti->name, fti->subscript);
        else if (fti->flags & OE_FLAG_PTR)
            Iprintf(depth, "%s* = ", fti->name);
        else
            Iprintf(depth, "%s = ", fti->name);

        if (fti->flags & OE_FLAG_UNCHECKED)
        {
            OE_PRINTF("<unchecked type>\n");
        }
        else if (fti->flags & OE_FLAG_PTR)
        {
            const void* ptr = *(const void**)p;
            size_t elemSize = _GetTypeSize(fti);
            size_t arrSize = 0xFFFFFFFF;

            if (ptr == NULL)
            {
                OE_PRINTF("NULL\n");
                continue;
            }
            else if (fti->flags & OE_FLAG_STRING)
            {
                _PrintArray(fti, ptr, elemSize, 0xFFFFFFFF, depth);
                OE_PRINTF("\n");
            }
            else if (fti->flags & OE_FLAG_COUNT)
            {
                if (_GetCount(ti, structIn, fti, &arrSize) != OE_OK)
                {
                    OE_PRINTF("\n");
                    continue;
                }

                _PrintArray(fti, ptr, elemSize, arrSize, depth);
                OE_PRINTF("\n");
            }
        }
        else if (fti->flags & OE_FLAG_ARRAY)
        {
            _PrintArray(
                fti, p, fti->size / fti->subscript, fti->subscript, depth);
            OE_PRINTF("\n");
        }
        else
        {
            _PrintScalar(fti, p, depth);
            OE_PRINTF("\n");
        }
    }

    depth--;
    Iprintf(depth, "}");
}
#endif

#ifndef SUPPRESS_OUTPUT_FUNCTIONS
void oe_print_struct(const oe_struct_ti_t* ti, const void* structIn)
{
    _PrintStruct(ti, structIn, 0);
    OE_PRINTF("\n");
}
#endif

/*
**==============================================================================
**
** Lifetime management:
**
**==============================================================================
*/

static oe_result_t _CopyStructs(
    const oe_struct_ti_t* ti,
    const void* structIn,
    size_t count,
    void* structOut,
    void*(alloc)(size_t size))
{
    const uint8_t* src = (uint8_t*)structIn;
    uint8_t* dest = (uint8_t*)structOut;

    /* Copy construct each struct onto array memory */
    for (size_t i = 0; i < count; i++)
    {
        oe_result_t result;

        if ((result = oe_copy_struct(ti, src, dest, alloc)) != OE_OK)
            return result;

        src += ti->size;
        dest += ti->size;
    }

    return OE_OK;
}

static oe_result_t _ClonePtrField(
    const oe_struct_ti_t* sti,
    const void* sin,
    const oe_field_ti_t* fti,
    const void* ptrIn,
    void** ptrOut,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;
    size_t count = 0;

    if (ptrOut)
        *ptrOut = NULL;

    if (!sti || !sin || !fti || !ptrIn || !ptrOut || (alloc == NULL))
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(_GetCount(sti, sin, fti, &count));

    if (fti->flags & OE_FLAG_STRING)
    {
        if (fti->type == OE_CHAR_T)
        {
            if (!(*ptrOut = _Strdup((char*)ptrIn, count, alloc)))
                OE_THROW(OE_OUT_OF_MEMORY);
        }
    }
    else if (fti->flags & OE_FLAG_COUNT)
    {
        size_t size;

        /* Get the size of an element */
        size = _GetTypeSize(fti);

        /* Allocate enough memory to hold object(s) */
        if (!(*ptrOut = alloc(size * count)))
            OE_THROW(OE_OUT_OF_MEMORY);

        /* Clear output memory */
        memset(*ptrOut, 0, size * count);

        /* Handle struct-pointers with [count] qualifier */
        if (fti->type == OE_STRUCT_T)
        {
            OE_TRY(_CopyStructs(fti->sti, ptrIn, count, *ptrOut, alloc));
        }
        else
        {
            memcpy(*ptrOut, ptrIn, size * count);
        }
    }
    else
    {
        /* ATTN: Handle other pointer types */
        OE_THROW(OE_UNEXPECTED);
    }

    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
    {
        if (ptrOut && *ptrOut)
        {
            *ptrOut = NULL;
        }
    }

    return result;
}

static oe_result_t _CopyField(
    const oe_struct_ti_t* sti,
    const void* sin,
    const oe_field_ti_t* fti,
    const void* fin,
    void* fout,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;

    /* Check for null parameters */
    if (!fti || !fin || !fout || (alloc == NULL))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Zero-initialize this field */
    memset(fout, 0, fti->size);

    if (fti->flags & OE_FLAG_UNCHECKED)
    {
        /* Copy over [unchecked] field as-is */
        memcpy(fout, fin, fti->size);
    }
    else if (fti->flags & OE_FLAG_PTR)
    {
        const void* finp = *(const void**)fin;
        void* foutp = NULL;

        if (!finp)
            OE_THROW(OE_OK);

        OE_TRY(_ClonePtrField(sti, sin, fti, finp, &foutp, alloc));

        *(void**)fout = foutp;
    }
    else if (fti->flags & OE_FLAG_ARRAY)
    {
        if (fti->type == OE_STRUCT_T)
            OE_TRY(_CopyStructs(fti->sti, fin, fti->subscript, fout, alloc));
        else
            memcpy(fout, fin, fti->size);
    }
    else /* scalar */
    {
        if (fti->type == OE_STRUCT_T)
            OE_TRY(oe_copy_struct(fti->sti, fin, fout, alloc));
        else
            memcpy(fout, fin, fti->size);
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

static oe_result_t _DestroyStructs(
    const oe_struct_ti_t* sti,
    void* structs,
    size_t count,
    oe_dealloc_proc_t dealloc)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* p = (uint8_t*)structs;

    if (!sti || !structs || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    for (size_t i = 0; i < count; i++)
    {
        OE_TRY(oe_destroy_struct(sti, p, dealloc));
        p += sti->size;
    }

    return OE_OK;

OE_CATCH:

    return result;
}

oe_result_t oe_copy_struct(
    const oe_struct_ti_t* sti,
    const void* sin,
    void* sout,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    /* Check for null parameters */
    if (!sti || !sin || !sout || (alloc == NULL))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Zero-initialize destination structure */
    memset(sout, 0, sti->size);

    /* For each field */
    for (i = 0; i < sti->nfields; i++)
    {
        const oe_field_ti_t* fti = &sti->fields[i];
        const void* fin = (const uint8_t*)sin + fti->offset;
        void* fout = (uint8_t*)sout + fti->offset;
        OE_TRY(_CopyField(sti, sin, fti, fin, fout, alloc));
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

oe_result_t oe_clone_struct(
    const oe_struct_ti_t* sti,
    const void* sin,
    void** sout,
    void*(alloc)(size_t size))
{
    if (sout)
        *sout = NULL;

    /* Check for null parameters */
    if (!sti || !sin || (alloc == NULL))
        return OE_INVALID_PARAMETER;

    /* Allocate new structure (allocate at least 1 byte) */
    if (!(*sout = alloc(sti->size > 0 ? sti->size : 1)))
        return OE_OUT_OF_MEMORY;

    return oe_copy_struct(sti, sin, *sout, alloc);
}

static oe_result_t _CloneStructs(
    const oe_struct_ti_t* sti,
    const void* sin,
    size_t count,
    void** sout,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;

    if (!sti || !sin || !count || !sout || (alloc == NULL))
        OE_THROW(OE_INVALID_PARAMETER);

    if (!(*sout = alloc(sti->size * count)))
        return OE_OUT_OF_MEMORY;

    OE_TRY(_CopyStructs(sti, sin, count, *sout, alloc));

    result = OE_OK;

OE_CATCH:
    return result;
}

static oe_result_t _CloneBlob(
    const void* dataIn,
    size_t size,
    void** dataOut,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;

    if (!dataIn || !size || !dataOut || (alloc == NULL))
        OE_THROW(OE_INVALID_PARAMETER);

    if (!(*dataOut = alloc(size)))
        return OE_OUT_OF_MEMORY;

    memcpy(*dataOut, dataIn, size);

    result = OE_OK;

OE_CATCH:
    return result;
}

static oe_result_t _ApplyStructPtrProc(
    const oe_struct_ti_t* ti,
    void* strct,
    void (*proc)(void* ptr, size_t size, void* procData),
    void* procData);

/* Apply the proc() function to every pointer within the struct array */
static oe_result_t _ApplyStructsPtrProc(
    const oe_struct_ti_t* ti,
    void* structs,
    size_t count,
    void (*proc)(void* ptr, size_t size, void* procData),
    void* procData)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    for (i = 0; i < count; i++)
    {
        void* s = (uint8_t*)structs + (i * ti->size);
        OE_TRY(_ApplyStructPtrProc(ti, s, proc, procData));
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

/* Apply the proc() function to every pointer within the struct */
static oe_result_t _ApplyStructPtrProc(
    const oe_struct_ti_t* ti,
    void* strct,
    void (*proc)(void* ptr, size_t size, void* procData),
    void* procData)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    if (!ti || !strct)
        OE_THROW(OE_INVALID_PARAMETER);

    /* For each field */
    for (i = 0; i < ti->nfields; i++)
    {
        const oe_field_ti_t* fti = &ti->fields[i];
        uint8_t* fptr = (uint8_t*)strct + fti->offset;

        if (fti->flags & OE_FLAG_UNCHECKED)
        {
            /* Cannot release unchecked objects */
        }
        else if (fti->flags & OE_FLAG_PTR && fti->flags & OE_FLAG_ARRAY)
        {
            OE_THROW(OE_UNSUPPORTED);
        }
        else if (fti->flags & OE_FLAG_PTR)
        {
            void* ptr = *(void**)fptr;

            /* Skip null pointers */
            if (!ptr)
                continue;

            /* Handle character pointers with [cstring] qualifier */
            if (fti->flags & OE_FLAG_STRING)
            {
                if (fti->type == OE_CHAR_T)
                {
                    /* ATTN: how do we get the true size? */
                    size_t bytes = _SizeofStr((const char*)ptr);
                    proc(ptr, bytes, procData);
                }
            }
            else if (fti->flags & OE_FLAG_COUNT)
            {
                size_t count;

                /* Get number of elements in this pointer array */
                OE_TRY(_GetCount(ti, strct, fti, &count));

                /* Handle struct-pointers with [count] qualifier */
                if (fti->type == OE_STRUCT_T)
                {
                    OE_TRY(
                        _ApplyStructsPtrProc(
                            fti->sti, ptr, count, proc, procData));
                    proc(ptr, fti->sti->size * count, procData);
                }
                else
                {
                    size_t size = _GetTypeSize(fti);
                    proc(ptr, size * count, procData);
                }
            }
            else
                OE_THROW(OE_UNEXPECTED);
        }
        else if (fti->flags & OE_FLAG_ARRAY)
        {
            if (fti->type == OE_STRUCT_T)
            {
                OE_TRY(
                    _ApplyStructsPtrProc(
                        fti->sti, fptr, fti->subscript, proc, procData));
            }
        }
        else /* scalar */
        {
            if (fti->type == OE_STRUCT_T)
            {
                OE_TRY(_ApplyStructPtrProc(fti->sti, fptr, proc, procData));
            }
        }
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static void _FreeProc(void* ptr, size_t size, void* procData)
{
    oe_dealloc_proc_t proc = (oe_dealloc_proc_t)procData;

    if (proc)
        proc(ptr);
}

oe_result_t oe_destroy_struct(
    const oe_struct_ti_t* ti,
    void* strct,
    oe_dealloc_proc_t dealloc)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!ti || !strct || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(_ApplyStructPtrProc(ti, strct, _FreeProc, dealloc));

    memset(strct, 0, ti->size);

    result = OE_OK;

OE_CATCH:

    return result;
}

oe_result_t oe_free_struct(
    const oe_struct_ti_t* ti,
    void* strct,
    oe_dealloc_proc_t dealloc)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!ti || !strct || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(oe_destroy_struct(ti, strct, dealloc));
    dealloc(strct);

    result = OE_OK;

OE_CATCH:
    return result;
}

oe_result_t oe_clear_arg(
    const oe_struct_ti_t* sti,
    void* sin,
    size_t index,
    bool isPtrPtr,
    void* arg,
    oe_dealloc_proc_t dealloc)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_field_ti_t* fti;
    size_t count = 0;

    if (!sti || !sin || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Function arguments can be null */
    if (!arg)
        OE_THROW(OE_OK);

    if (index >= sti->nfields)
        OE_THROW(OE_OUT_OF_BOUNDS);

    if (!(fti = &sti->fields[index]))
        OE_THROW(OE_UNEXPECTED);

    if (fti->flags & OE_FLAG_COUNT)
        OE_TRY(_GetCount(sti, sin, fti, &count));

    if (fti->flags & OE_FLAG_UNCHECKED)
    {
        memset(arg, 0, fti->size);
    }
    else if (fti->flags & OE_FLAG_PTR)
    {
        if (fti->flags & OE_FLAG_STRING)
        {
            if (isPtrPtr)
            {
                void* ptr = *(void**)arg;

                if (!ptr)
                    OE_THROW(OE_OK);

                if (fti->type == OE_CHAR_T)
                {
                    dealloc(ptr);
                    *(void**)arg = NULL;
                }
                else
                    OE_THROW(OE_UNEXPECTED);
            }
            else
            {
                if (!count)
                    OE_THROW(OE_UNEXPECTED);

                if (fti->type == OE_CHAR_T)
                    memset(arg, 0, count * sizeof(char));
            }
        }
        else if (fti->flags & OE_FLAG_COUNT)
        {
            if (fti->type == OE_STRUCT_T)
            {
                if (!count)
                    OE_THROW(OE_UNEXPECTED);

                if (isPtrPtr)
                {
                    void* ptr = *(void**)arg;

                    if (!ptr)
                        OE_THROW(OE_OK);

                    OE_TRY(_DestroyStructs(fti->sti, ptr, count, dealloc));

                    dealloc(ptr);
                    *(void**)arg = NULL;
                }
                else
                    OE_TRY(_DestroyStructs(fti->sti, arg, count, dealloc));
            }
            else
            {
                if (isPtrPtr)
                {
                    void* ptr = *(void**)arg;

                    if (!ptr)
                        OE_THROW(OE_OK);

                    dealloc(ptr);
                    *(void**)arg = NULL;
                }
                else
                {
                    if (!count)
                        OE_THROW(OE_UNEXPECTED);

                    memset(arg, 0, _GetTypeSize(fti) * count);
                }
            }
        }
        else
        {
            OE_THROW(OE_UNEXPECTED);
        }
    }
    else if (fti->flags & OE_FLAG_ARRAY)
    {
        if (fti->flags & OE_FLAG_STRING)
        {
            if (fti->type == OE_CHAR_T)
            {
                memset(arg, 0, fti->subscript * sizeof(char));
            }
            else
            {
                OE_THROW(OE_UNEXPECTED);
            }
        }
        else if (fti->type == OE_STRUCT_T)
        {
            OE_TRY(_DestroyStructs(fti->sti, arg, fti->subscript, dealloc));
        }
        else
        {
            memset(arg, 0, _GetTypeSize(fti) * fti->subscript);
        }
    }
    else /* scalar */
    {
        if (fti->type == OE_STRUCT_T)
            OE_TRY(_DestroyStructs(fti->sti, arg, 1, dealloc));
        else
            memset(arg, 0, fti->size);
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

size_t oe_struct_find_field(const oe_struct_ti_t* sti, const char* name)
{
    if (!sti || !name)
        return (size_t)-1;

    for (size_t i = 0; i < sti->nfields; i++)
    {
        if (strcmp(sti->fields[i].name, name) == 0)
            return i;
    }

    return (size_t)-1;
}

oe_result_t oe_clear_arg_by_name(
    const oe_struct_ti_t* sti,
    void* strct,
    const char* name,
    bool isPtrPtr,
    void* arg,
    oe_dealloc_proc_t dealloc)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t index;

    if (!sti || !strct || !name || !arg || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    index = oe_struct_find_field(sti, name);

    if (index == (size_t)-1)
        OE_THROW(OE_NOT_FOUND);

    OE_TRY(oe_clear_arg(sti, strct, index, isPtrPtr, arg, dealloc));

    result = OE_OK;

OE_CATCH:
    return result;
}

oe_result_t oe_set_arg(
    const oe_struct_ti_t* sti,
    void* sin,
    size_t index,
    bool isPtrPtr,
    void* arg,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_field_ti_t* fti = NULL;
    const void* field;
    size_t count = 0;

    /* Check null parameters */
    if (!sti || !sin)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Null functions arguments are permitted */
    if (!arg)
        OE_THROW(OE_OK);

    /* Check for bounds error */
    if (index >= sti->nfields)
        OE_THROW(OE_OUT_OF_BOUNDS);

    /* Set pointer to field type information */
    if (!(fti = &sti->fields[index]))
        OE_THROW(OE_UNEXPECTED);

    /* Set pointer to field value */
    field = (uint8_t*)sin + fti->offset;

    /* Get value of count field if any */
    if (fti->flags & OE_FLAG_COUNT)
        OE_TRY(_GetCount(sti, sin, fti, &count));

    if (fti->flags & OE_FLAG_UNCHECKED)
    {
        memcpy(arg, field, fti->size);
    }
    else if (fti->flags & OE_FLAG_PTR)
    {
        void* fp = *(void**)field;
        void** app = (void**)arg;

        if (!fp)
            OE_THROW(OE_OK);

        /* Prevent copying over the same object */
        if (fp == arg)
            OE_THROW(OE_OVERLAPPED_COPY);

        if (fti->flags & OE_FLAG_STRING)
        {
            if (isPtrPtr)
            {
                if (fti->type == OE_CHAR_T)
                {
                    if (!(*app = _Strdup((const char*)fp, count, alloc)))
                        OE_THROW(OE_OUT_OF_MEMORY);
                }
                else
                    OE_THROW(OE_UNEXPECTED);
            }
            else
            {
                if (!count)
                    OE_THROW(OE_UNEXPECTED);

                if (fti->type == OE_CHAR_T)
                    memcpy(arg, fp, count * sizeof(char));
                else
                    OE_THROW(OE_UNEXPECTED);
            }
        }
        else if (fti->flags & OE_FLAG_COUNT)
        {
            if (!count)
                OE_THROW(OE_UNEXPECTED);

            if (isPtrPtr)
            {
                if (fti->type == OE_STRUCT_T)
                    OE_TRY(_CloneStructs(fti->sti, fp, count, app, alloc));
                else
                {
                    size_t size = _GetTypeSize(fti);
                    OE_TRY(_CloneBlob(fp, size * count, app, alloc));
                }
            }
            else
            {
                if (fti->type == OE_STRUCT_T)
                    OE_TRY(_CopyStructs(fti->sti, fp, count, arg, alloc));
                else
                {
                    size_t size = _GetTypeSize(fti);
                    memcpy(arg, fp, size * count);
                }
            }
        }
        else
        {
            OE_THROW(OE_UNEXPECTED);
        }
    }
    else if (fti->flags & OE_FLAG_ARRAY)
    {
        size_t count = fti->subscript;

        if (arg == field)
            OE_THROW(OE_OVERLAPPED_COPY);

        if (fti->flags & OE_FLAG_STRING)
        {
            if (fti->type == OE_CHAR_T)
                memcpy(arg, field, count * sizeof(char));
            else
                OE_THROW(OE_UNEXPECTED);
        }
        else if (fti->type == OE_STRUCT_T)
            OE_TRY(_CopyStructs(fti->sti, field, count, arg, alloc));
        else
            memcpy(arg, field, fti->size);
    }
    else /* scalar */
    {
        if (arg == field)
            OE_THROW(OE_OVERLAPPED_COPY);

        if (fti->type == OE_STRUCT_T)
            OE_TRY(_CopyStructs(fti->sti, field, 1, arg, alloc));
        else
            memcpy(arg, field, fti->size);
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

oe_result_t oe_init_arg(
    const oe_struct_ti_t* sti,
    void* sin,
    size_t index,
    bool isPtrPtr,
    void* arg,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_field_ti_t* fti = NULL;
    size_t count = 0;

    /* Check null parameters */
    if (!sti || !sin || !arg)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Check for bounds error */
    if (index >= sti->nfields)
        OE_THROW(OE_OUT_OF_BOUNDS);

    /* Get pointer to field type information */
    if (!(fti = &sti->fields[index]))
        OE_THROW(OE_UNEXPECTED);

    /* Get value of count field if any */
    if (fti->flags & OE_FLAG_COUNT)
        OE_TRY(_GetCount(sti, sin, fti, &count));

    if (fti->flags & OE_FLAG_UNCHECKED)
    {
        // memset(arg, 0, fti->size);
    }
    else if (fti->flags & OE_FLAG_PTR)
    {
        void** app = (void**)arg;

        if (fti->flags & OE_FLAG_STRING)
        {
            if (!count)
                OE_THROW(OE_UNEXPECTED);

            if (isPtrPtr)
            {
                if (fti->type == OE_CHAR_T)
                {
                    if (!(*app = _Calloc(count * sizeof(char), alloc)))
                        OE_THROW(OE_OUT_OF_MEMORY);
                }
                else
                    OE_THROW(OE_UNEXPECTED);
            }
            else
            {
                if (fti->type == OE_CHAR_T)
                    ; // memset(arg, 0, count * sizeof(char));
            }
        }
        else if (fti->flags & OE_FLAG_COUNT)
        {
            if (!count)
                OE_THROW(OE_UNEXPECTED);

            if (isPtrPtr)
            {
                if (!(*app = _Calloc(_GetTypeSize(fti) * count, alloc)))
                    OE_THROW(OE_OUT_OF_MEMORY);
            }
            else
            {
                ; // memset(arg, 0, _GetTypeSize(fti) * count);
            }
        }
        else
        {
            OE_THROW(OE_UNEXPECTED);
        }
    }
    else if (fti->flags & OE_FLAG_ARRAY)
    {
        ; // memset(arg, 0, fti->size);
    }
    else /* scalar */
    {
        ; // memset(arg, 0, _GetTypeSize(fti));
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

oe_result_t oe_set_arg_by_name(
    const oe_struct_ti_t* sti,
    void* strct,
    const char* name,
    bool isPtrPtr,
    void* arg,
    void*(alloc)(size_t size))
{
    oe_result_t result = OE_UNEXPECTED;
    size_t index;

    if (!sti || !strct || !name || !arg)
        OE_THROW(OE_INVALID_PARAMETER);

    index = oe_struct_find_field(sti, name);

    if (index == (size_t)-1)
        OE_THROW(OE_NOT_FOUND);

    OE_TRY(oe_set_arg(sti, strct, index, isPtrPtr, arg, alloc));

    result = OE_OK;

OE_CATCH:
    return result;
}

static oe_result_t _CheckOptConstraint(
    const oe_struct_ti_t* sti,
    const void* sin,
    const oe_field_ti_t* fti)
{
    oe_result_t result = OE_UNEXPECTED;
    const void* fin;

    if (!sti || !sin || !fti)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Ignore pointer check if this field has the [opt] qualifier */
    if ((fti->flags & OE_FLAG_OPT))
        OE_THROW(OE_OK);

    /* ATTN: Ignore references for now (not sure how to check a reference) */
    if ((fti->flags & OE_FLAG_REF))
        OE_THROW(OE_OK);

    /* Ignore pointer check if this field is not a pointer */
    if (!(fti->flags & OE_FLAG_PTR))
        OE_THROW(OE_OK);

    /* Calculate offset of this field within the structure */
    fin = (const uint8_t*)sin + fti->offset;

    /* If pointer at this address is null, then fail */
    if (!*(void**)fin)
        OE_THROW(OE_CONSTRAINT_FAILED);

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

oe_result_t oe_check_pre_constraints(const oe_struct_ti_t* sti, const void* sin)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    if (!sti || !sin)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        const oe_field_ti_t* fti = &sti->fields[i];

        if (!fti)
            OE_THROW(OE_UNEXPECTED);

        /* Check for missing [opt] constraint */
        if (!(fti->flags & OE_FLAG_OPT))
        {
            /* Do not apply check to the return value */
            if (i != 0)
                OE_TRY(_CheckOptConstraint(sti, sin, fti));
        }
    }

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

oe_result_t oe_check_post_constraints(
    const oe_struct_ti_t* sti,
    const void* sin)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    if (!sti || !sin)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        const oe_field_ti_t* fti = &sti->fields[i];

        if (!fti)
            OE_THROW(OE_UNEXPECTED);

        /* Check for missing [opt] constraint */
        if (!(fti->flags & OE_FLAG_OPT))
        {
            OE_TRY(_CheckOptConstraint(sti, sin, fti));
        }
    }

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

static oe_result_t _TestOrFillPadding(
    const oe_struct_ti_t* sti,
    const void* sin,
    bool test, /* test if true; fill sif false */
    uint8_t byte)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i = 0;

    if (!sti || !sin)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        const oe_field_ti_t* fti = &sti->fields[i];
        void* fin;
        uint8_t* start;
        uint8_t* end;

        if (!fti)
            OE_THROW(OE_UNEXPECTED);

        /* Set 'fin' to point to this field */
        fin = (uint8_t*)sin + fti->offset;

        /* Set 'start' to the end of this field */
        start = (uint8_t*)fin + fti->size;

        /* Set 'end' to next field, else the end of structure */
        if (i + 1 != sti->nfields)
        {
            const oe_field_ti_t* nfti = &sti->fields[i + 1];

            if (!nfti)
                OE_THROW(OE_UNEXPECTED);

            end = (uint8_t*)sin + nfti->offset;
        }
        else
        {
            end = (uint8_t*)sin + sti->size;
        }

        /* Test or fill the padding after this structure */
        while (start != end)
        {
            if (test)
            {
                if (*start++ != byte)
                    OE_THROW(OE_OUT_OF_BOUNDS);
            }
            else
                *start++ = byte;
        }

/* This code breaks ECALLs and OCALLs where the callee changes
 * the contents of one of the structure arguments.
 */
#if 0
        /* Recurse if this field is a structure */
        if (fti->type == OE_STRUCT_T)
        {
            size_t n = 0;
            uint8_t* p;

            if (fti->flags & OE_FLAG_COUNT)
                OE_TRY(_GetCount(sti, sin, fti, &n));

            if (fti->flags & OE_FLAG_PTR)
            {
                p = *(void**)fin;
                if (!p)
                    n = 0;
            }
            else if (fti->flags & OE_FLAG_ARRAY)
            {
                p = fin;
                n = fti->subscript;
            }
            else
            {
                p = fin;
                n = 1;
            }

            while (n--)
            {
                OE_TRY(_TestOrFillPadding(fti->sti, p, test, byte));
                p += fti->sti->size;
            }
        }
#endif
    }

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

oe_result_t oe_test_struct_padding(const oe_struct_ti_t* sti, const void* sin)
{
    return _TestOrFillPadding(sti, sin, true, 0xAA);
}

oe_result_t oe_pad_struct(const oe_struct_ti_t* sti, const void* sin)
{
    return _TestOrFillPadding(sti, sin, false, 0xAA);
}

oe_result_t oe_check_struct(const oe_struct_ti_t* ti, void* strct)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!ti || !strct)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(oe_test_struct_padding(ti, strct));

    result = OE_OK;

OE_CATCH:

    return result;
}
