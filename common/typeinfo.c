#define OE_TRACE_LEVEL 0
#include <openenclave.h>
#include <oeinternal/galloc.h>

#ifdef OE_BUILD_ENCLAVE
# include <openenclave.h>
#endif

#ifndef OE_BUILD_ENCLAVE
# include <string.h>
# include <stdlib.h>
# include <stdio.h>
# include <wchar.h>
# include <ctype.h>
# include <stdarg.h>
# include <openenclave.h>
#endif

#define TRACE OE_Printf("TRACE: %s(%u): %s\n", __FILE__, __LINE__, __FUNCTION__)

#define PRINTF printf

/*
**==============================================================================
**
** Utility functions:
**
**==============================================================================
*/

#ifdef OE_BUILD_ENCLAVE
# define WCSLEN OE_Wcslen
# define STRLEN OE_Strlen
# define STRCMP OE_Strcmp
# define MEMCMP OE_Memcmp
# define WCSCMP OE_Wcscmp
# define MEMSET OE_Memset
# define MEMCPY OE_Memcpy
#else
# define WCSLEN wcslen
# define STRLEN strlen
# define STRCMP strcmp
# define MEMCMP memcmp
# define WCSCMP wcscmp
# define MEMSET memset
# define MEMCPY memcpy
#endif

static void* _Calloc(
    oe_size_t n,
    void* (alloc)(oe_size_t size))
{
    void* p;

    if (!(p = alloc(n)))
        return OE_NULL;

    return MEMSET(p, 0, n);
}

static char* _Strdup(
    const char* s,
    oe_size_t n,
    void* (alloc)(oe_size_t size))
{
    char* p;

    if (!s || !alloc)
        return OE_NULL;

    if (n == 0)
        n = STRLEN(s) + 1;

    if (!(p = (char*)alloc(n * sizeof(char))))
        return OE_NULL;

    MEMSET(p, 0, n * sizeof(char));
    return MEMCPY(p, s, n * sizeof(char));
}

static char* _Wcsdup(
    const oe_wchar_t* s,
    oe_size_t n,
    void* (alloc)(oe_size_t size))
{
    oe_wchar_t* p;

    if (!s || !alloc)
        return OE_NULL;

    if (n == 0)
        n = WCSLEN(s) + 1;

    if (!(p = (oe_wchar_t*)alloc(n * sizeof(oe_wchar_t))))
        return OE_NULL;

    MEMSET(p, 0, n * sizeof(char));
    return MEMCPY(p, s, n * sizeof(oe_wchar_t));
}

static oe_size_t _SizeofStr(const char* s)
{
    if (!s)
        return 0;

    return (STRLEN(s) + 1) * sizeof(char);
}

static oe_size_t _SizeofWcs(const oe_wchar_t* s)
{
    if (!s)
        return 0;

    return (WCSLEN(s) + 1) * sizeof(oe_wchar_t);
}

static OE_Result _StrToSize(const char* str, oe_size_t* size)
{
    oe_size_t r = 1;
    oe_size_t x = 0;
    oe_size_t n = 0;
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

static const OE_FieldTI* _FindFieldTI(
    const OE_StructTI* ti,
    const char* name)
{
    oe_size_t i;

    for (i = 0; i < ti->nfields; i++)
    {
        const OE_FieldTI* fti = &ti->fields[i];

        if (STRCMP(fti->name, name) == 0)
            return fti;
    }

    return OE_NULL;
}

static OE_Result _GetCount(
    const OE_StructTI* ti,
    const void* structIn,
    const OE_FieldTI* fti,
    oe_size_t* count)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_FieldTI* cfti;

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

    /* Check type of count field (oe_size_t) */
    if (cfti->type != OE_SIZE_T)
        OE_THROW(OE_WRONG_TYPE);

    /* Read the count field from the structure */
    *count = *(const oe_size_t*)((const oe_uint8_t*)structIn + cfti->offset);

    result = OE_OK;

catch:
    return result;
}

/* Get the size of the given type */
static oe_size_t _GetTypeSizeFromType(
    OE_Type type)
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
        case OE_LONG_T: 
            return sizeof(long);
        case OE_USHORT_T: 
            return sizeof(unsigned short);
        case OE_UINT_T: 
            return sizeof(unsigned int);
        case OE_ULONG_T: 
            return sizeof(unsigned long);
#if 0 /* REMOVE */
        case OE_UCHAR_T: 
            return sizeof(oe_uchar);
        case OE_LLONG_T: 
            return sizeof(oe_llong);
        case OE_ULLONG_T: 
            return sizeof(oe_ullong);
        case OE_INTN_T: 
            return sizeof(oe_intn);
        case OE_UINTN_T: 
            return sizeof(oe_uintn);
#endif
        case OE_WCHAR_T: 
            return sizeof(oe_wchar_t);
        case OE_BOOL_T: 
            return sizeof(oe_bool);
        case OE_INT8_T: 
            return sizeof(oe_int8_t);
        case OE_UCHAR_T: 
        case OE_UINT8_T: 
            return sizeof(oe_uint8_t);
        case OE_INT16_T: 
            return sizeof(oe_int16_t);
        case OE_UINT16_T: 
            return sizeof(oe_uint16_t);
        case OE_INT32_T: 
            return sizeof(oe_int32_t);
        case OE_UINT32_T: 
            return sizeof(oe_uint32_t);
        case OE_INT64_T: 
            return sizeof(oe_int64_t);
        case OE_UINT64_T: 
            return sizeof(oe_uint64_t);
        case OE_FLOAT_T: 
            return sizeof(float);
        case OE_DOUBLE_T: 
            return sizeof(double);
        case OE_SIZE_T: 
            return sizeof(oe_size_t);
        case OE_SSIZE_T: 
            return sizeof(oe_ssize_t);
        case OE_STRUCT_T: 
            return 0;
        case OE_VOID_T: 
            return 1;
    }

    return 0;
}

/* Get type-size of this field (not necessarily the same as field size) */
static oe_size_t _GetTypeSize(
    const OE_FieldTI* fti)
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

static oe_bool _ScalarEq(
    OE_Type type,
    const void* p1,
    const void* p2)
{
    switch (type)
    {
        case OE_NONE_T:
            return oe_false;
        case OE_CHAR_T:
            return *((char*)p1) == *((char*)p2);
        case OE_SHORT_T:
            return *((short*)p1) == *((short*)p2);
        case OE_INT_T:
            return *((int*)p1) == *((int*)p2);
        case OE_LONG_T:
            return *((long*)p1) == *((long*)p2);
        case OE_USHORT_T:
            return *((unsigned short*)p1) == *((unsigned short*)p2);
        case OE_UINT_T:
            return *((unsigned int*)p1) == *((unsigned int*)p2);
        case OE_ULONG_T:
            return *((unsigned long*)p1) == *((unsigned long*)p2);
#if 0 /* REMOVE */
        case OE_UCHAR_T:
            return *((oe_uchar*)p1) == *((oe_uchar*)p2);
        case OE_LLONG_T:
            return *((oe_llong*)p1) == *((oe_llong*)p2);
        case OE_ULLONG_T:
            return *((oe_ullong*)p1) == *((oe_ullong*)p2);
        case OE_INTN_T:
            return *((oe_intn*)p1) == *((oe_intn*)p2);
        case OE_UINTN_T:
            return *((oe_uintn*)p1) == *((oe_uintn*)p2);
#endif
        case OE_WCHAR_T:
            return *((oe_wchar_t*)p1) == *((oe_wchar_t*)p2);
        case OE_BOOL_T:
            return *((oe_bool*)p1) == *((oe_bool*)p2);
        case OE_INT8_T:
            return *((oe_int8_t*)p1) == *((oe_int8_t*)p2);
        case OE_UCHAR_T:
        case OE_UINT8_T:
            return *((oe_uint8_t*)p1) == *((oe_uint8_t*)p2);
        case OE_INT16_T:
            return *((oe_int16_t*)p1) == *((oe_int16_t*)p2);
        case OE_UINT16_T:
            return *((oe_uint16_t*)p1) == *((oe_uint16_t*)p2);
        case OE_INT32_T:
            return *((oe_int32_t*)p1) == *((oe_int32_t*)p2);
        case OE_UINT32_T:
            return *((oe_uint32_t*)p1) == *((oe_uint32_t*)p2);
        case OE_INT64_T:
            return *((oe_int64_t*)p1) == *((oe_int64_t*)p2);
        case OE_UINT64_T:
            return *((oe_uint64_t*)p1) == *((oe_uint64_t*)p2);
        case OE_FLOAT_T:
            return *((float*)p1) == *((float*)p2);
        case OE_DOUBLE_T:
            return *((double*)p1) == *((double*)p2);
        case OE_SIZE_T:
            return *((oe_size_t*)p1) == *((oe_size_t*)p2);
        case OE_SSIZE_T:
            return *((oe_ssize_t*)p1) == *((oe_ssize_t*)p2);
        case OE_STRUCT_T:
            return oe_false;
        case OE_VOID_T:
            return oe_false;
    }

    /* Unreachable */
    return oe_false;
}

static oe_bool _Real32Eq(
    const float* p1,
    const float* p2,
    oe_size_t n)
{
    oe_size_t i;

    for (i = 0; i < n; i++)
        if (p1[i] != p2[i])
            return oe_false;

    return oe_true;
}

static oe_bool _Real64Eq(
    const double* p1,
    const double* p2,
    oe_size_t n)
{
    oe_size_t i;

    for (i = 0; i < n; i++)
        if (p1[i] != p2[i])
            return oe_false;

    return oe_true;
}

static oe_bool _BytesEq(const void* p1, const void* p2, oe_size_t n)
{
    return MEMCMP(p1, p2, n) == 0 ? oe_true : oe_false;
}

static oe_bool _ArrayEq(
    OE_Type type,
    const void* p1,
    const void* p2,
    oe_size_t n)
{
    switch (type)
    {
        case OE_NONE_T:
            return oe_false;
        case OE_CHAR_T:
            return _BytesEq(p1, p2, sizeof(char) * n);
        case OE_WCHAR_T:
            return _BytesEq(p1, p2, sizeof(oe_wchar_t) * n);
        case OE_BOOL_T:
            return _BytesEq(p1, p2, sizeof(oe_bool) * n);
        case OE_INT8_T:
            return _BytesEq(p1, p2, sizeof(oe_int8_t) * n);
        case OE_UCHAR_T:
        case OE_UINT8_T:
            return _BytesEq(p1, p2, sizeof(oe_uint8_t) * n);
        case OE_SHORT_T:
        case OE_INT16_T:
            return _BytesEq(p1, p2, sizeof(oe_int16_t) * n);
        case OE_USHORT_T:
        case OE_UINT16_T:
            return _BytesEq(p1, p2, sizeof(oe_uint16_t) * n);
        case OE_INT_T:
        case OE_INT32_T:
            return _BytesEq(p1, p2, sizeof(oe_int32_t) * n);
        case OE_UINT_T:
        case OE_UINT32_T:
            return _BytesEq(p1, p2, sizeof(oe_uint32_t) * n);
        case OE_LONG_T:
        case OE_INT64_T:
            return _BytesEq(p1, p2, sizeof(oe_int64_t) * n);
        case OE_ULONG_T:
        case OE_UINT64_T:
            return _BytesEq(p1, p2, sizeof(oe_uint64_t) * n);
        case OE_FLOAT_T:
            return _Real32Eq(p1, p2, sizeof(float) * n);
        case OE_DOUBLE_T:
            return _Real64Eq(p1, p2, sizeof(double) * n);
        case OE_SIZE_T:
            return _BytesEq(p1, p2, sizeof(oe_size_t) * n);
        case OE_SSIZE_T:
            return _BytesEq(p1, p2, sizeof(oe_ssize_t) * n);
        case OE_STRUCT_T:
            return oe_false;
        case OE_VOID_T:
            return oe_false;
    }

    /* Unreachable */
    return oe_false;
}

static OE_Result _StructsEq(
    const OE_StructTI* sti,
    const void* s1,
    const void* s2,
    oe_size_t count,
    oe_bool* flag)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i;

    if (flag)
        *flag = oe_false;

    if (!sti || !s1 || !s2 || !flag)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < count; i++)
    {
        oe_bool tmp;
        OE_TRY(OE_StructEq(sti, s1, s2, &tmp));
        if (!tmp)
            OE_THROW(OE_OK);
    }

    *flag = oe_true;
    result = OE_OK;

catch:
    return result;
}

static OE_Result _FieldEq(
    const OE_StructTI* sti,
    const void* s1,
    const void* s2,
    oe_size_t index,
    oe_bool* flag)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_FieldTI* fti;
    oe_size_t count1 = 0;
    oe_size_t count2 = 0;
    const oe_uint8_t* f1;
    const oe_uint8_t* f2;

    if (flag)
        *flag = oe_false;

    if (!sti || !s1 || !s2 || !flag)
        OE_THROW(OE_INVALID_PARAMETER);

    if (index >= sti->nfields)
        OE_THROW(OE_OUT_OF_BOUNDS);

    fti = &sti->fields[index];

#if (OE_TRACE_LEVEL >= 2)
    PRINTF("_FieldEq(): %s.%s\n", sti->name, fti->name);
#endif

    if (fti->flags & OE_FLAG_COUNT)
    {
        OE_TRY(_GetCount(sti, s1, fti, &count1));
        OE_TRY(_GetCount(sti, s2, fti, &count2));
    }

    if (count1 != count2)
        OE_THROW(OE_OK);

    f1 = (const oe_uint8_t*)s1 + fti->offset;
    f2 = (const oe_uint8_t*)s2 + fti->offset;

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

            *flag = oe_true;
            OE_THROW(OE_OK);
        }

        if (fti->flags & OE_FLAG_STRING)
        {
            if (fti->type == OE_CHAR_T)
            {
                if (STRCMP((const char*)p1, (const char*)p2) != 0)
                    OE_THROW(OE_OK);
            }
            else if (fti->type == OE_WCHAR_T)
            {
                if (WCSCMP((const oe_wchar_t*)p1, (const oe_wchar_t*)p2) != 0)
                    OE_THROW(OE_OK);
            }
            else
                OE_THROW(OE_UNEXPECTED);
        }
        else if (fti->type == OE_STRUCT_T)
        {
            oe_bool tmp;

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
                if (STRCMP((const char*)f1, (const char*)f2) != 0)
                    OE_THROW(OE_OK);
            }
            else if (fti->type == OE_WCHAR_T)
            {
                if (WCSCMP((const oe_wchar_t*)f1, (const oe_wchar_t*)f2) != 0)
                    OE_THROW(OE_OK);
            }
            else
                OE_THROW(OE_UNEXPECTED);
        }
        else if (fti->type == OE_STRUCT_T)
        {
            oe_bool tmp;
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
            oe_bool tmp;
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

    *flag = oe_true;
    result = OE_OK;

catch:
    return result;
}

OE_Result OE_StructEq(
    const OE_StructTI* sti,
    const void* s1,
    const void* s2,
    oe_bool* flag)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i;

    if (flag)
        *flag = oe_false;

    if (!sti || !s1 || !s2 || !flag)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        oe_bool tmp;
        OE_TRY(_FieldEq(sti, s1, s2, i, &tmp));
        if (!tmp)
            OE_THROW(OE_OK);
    }

    *flag = oe_true;
    result = OE_OK;

catch:
    return result;
}

/*
**==============================================================================
**
** Printing functions:
**
**==============================================================================
*/

#ifndef OE_BUILD_ENCLAVE
static void _Indent(oe_size_t n)
{
    for (oe_size_t i = 0; i < n; i++)
        PRINTF("    ");
}
#endif

#ifndef OE_BUILD_ENCLAVE
OE_PRINTF_FORMAT(2, 3)
static void Iprintf(oe_size_t n, const char* format, ...)
{
    _Indent(n);
    va_list ap;
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
}
#endif

#ifndef OE_BUILD_ENCLAVE
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

#ifndef OE_BUILD_ENCLAVE
#define FUNCTION _PrintWcs
#define TYPE oe_wchar_t
#define FORMAT "%C"
#define PREFIX "L"
#include "printstr.c"
#undef FUNCTION
#undef TYPE
#undef FORMAT
#undef PREFIX
#endif

#ifndef OE_BUILD_ENCLAVE
static void _PrintStruct(
    const OE_StructTI* ti,
    const void* structIn,
    oe_size_t depth);
#endif

#ifndef OE_BUILD_ENCLAVE
static void _PrintScalar(
    const OE_FieldTI* fti,
    const void* p,
    oe_size_t depth)
{
    switch (fti->type)
    {
        case OE_NONE_T:
            break;
        case OE_CHAR_T:
            PRINTF("%02X", *(const char*)p);
            break;
        case OE_WCHAR_T:
            PRINTF("%02X", *(const oe_wchar_t*)p);
            break;
        case OE_BOOL_T:
            PRINTF("%s", (*(const oe_bool*)p) ? "oe_true" : "oe_false");
            break;
        case OE_INT8_T:
            PRINTF("%d", *(const oe_int8_t*)p);
            break;
        case OE_UCHAR_T:
        case OE_UINT8_T:
            PRINTF("%u", *(const oe_uint8_t*)p);
            break;
        case OE_SHORT_T:
        case OE_INT16_T:
            PRINTF("%d", *(const oe_int16_t*)p);
            break;
        case OE_USHORT_T:
        case OE_UINT16_T:
            PRINTF("%u", *(const oe_uint16_t*)p);
            break;
        case OE_INT_T:
        case OE_INT32_T:
            PRINTF("%d", *(const oe_int32_t*)p);
            break;
        case OE_UINT_T:
        case OE_UINT32_T:
            PRINTF("%u", *(const oe_uint32_t*)p);
            break;
        case OE_LONG_T:
        case OE_INT64_T:
            PRINTF(OE_INT64_F, *(const oe_int64_t*)p);
            break;
        case OE_ULONG_T:
        case OE_UINT64_T:
            PRINTF(OE_INT64_F, *(const oe_uint64_t*)p);
            break;
        case OE_FLOAT_T:
            PRINTF("%f", *(const float*)p);
            break;
        case OE_DOUBLE_T:
            PRINTF("%lf", *(const double*)p);
            break;
        case OE_SIZE_T:
            PRINTF("%zu", *(const oe_size_t*)p);
            break;
        case OE_SSIZE_T:
            PRINTF("%zd", *(const oe_ssize_t*)p);
            break;
        case OE_STRUCT_T:
            _PrintStruct(fti->sti, p, depth);
            break;
        case OE_VOID_T:
            PRINTF("%02X", *(const oe_uint8_t*)p);
            break;
    }
}
#endif

#ifndef OE_BUILD_ENCLAVE
static void _PrintArray(
    const OE_FieldTI* fti,
    const void* arr,
    oe_size_t elemSize, // elemSize in bytes of one elements:
    oe_size_t arrSize, // number of total elements:
    oe_size_t depth)
{
    const unsigned char* p = (const unsigned char*)arr;
    oe_bool lineSeparated = oe_false;

    if (fti->flags & OE_FLAG_STRING)
    {
        if (fti->type == OE_CHAR_T)
            _PrintStr((const char*)p, arrSize);
        else if (fti->type == OE_WCHAR_T)
            _PrintWcs((const oe_wchar_t*)p, arrSize);
        return;
    }

    if (fti->type == OE_STRUCT_T)
        lineSeparated = oe_true;

    if (lineSeparated)
    {
        PRINTF("\n");
        Iprintf(depth, "{\n");
        depth++;
        _Indent(depth);
    }
    else
        PRINTF("{ ");
    
    for (oe_size_t i = 0; i < arrSize; i++)
    {
        _PrintScalar(fti, p, depth);

        if (i + 1 != arrSize)
        {
            PRINTF(", ");
            if (lineSeparated)
            {
                PRINTF("\n");
                _Indent(depth);
            }
        }
        else
            PRINTF(" ");

        p += elemSize;
    }

    if (lineSeparated)
    {
        depth--;
        PRINTF("\n");
        Iprintf(depth, "}");
    }
    else
        PRINTF("}");
}
#endif

#ifndef OE_BUILD_ENCLAVE
static void _PrintStruct(
    const OE_StructTI* ti,
    const void* structIn,
    oe_size_t depth)
{
    oe_size_t i;

    /* Check for null parameters */
    if (!ti)
        return;

    PRINTF("struct %s\n", ti->name);
    Iprintf(depth, "{\n");
    depth++;

    /* Print each field of this structure */
    for (i = 0; i < ti->nfields; i++)
    {
        const OE_FieldTI* fti = &ti->fields[i];
        const oe_uint8_t* p = (const oe_uint8_t*)structIn + fti->offset;

        if (fti->flags & OE_FLAG_ARRAY)
            Iprintf(depth, "%s[%u] = ", fti->name, fti->subscript);
        else if (fti->flags & OE_FLAG_PTR)
            Iprintf(depth, "%s* = ", fti->name);
        else
            Iprintf(depth, "%s = ", fti->name);

        if (fti->flags & OE_FLAG_UNCHECKED)
        {
            PRINTF("<unchecked type>\n");
        }
        else if (fti->flags & OE_FLAG_PTR)
        {
            const void* ptr = *(const void**)p;
            oe_size_t elemSize = _GetTypeSize(fti);
            oe_size_t arrSize = 0xFFFFFFFF;

            if (ptr == OE_NULL)
            {
                PRINTF("OE_NULL\n");
                continue;
            }
            else if (fti->flags & OE_FLAG_STRING)
            {
                _PrintArray(fti, ptr, elemSize, 0xFFFFFFFF, depth);
                PRINTF("\n");
            }
            else if (fti->flags & OE_FLAG_COUNT)
            {
                if (_GetCount(ti, structIn, fti, &arrSize) != OE_OK)
                {
                    PRINTF("\n");
                    continue;
                }

                _PrintArray(fti, ptr, elemSize, arrSize, depth);
                PRINTF("\n");
            }
        }
        else if (fti->flags & OE_FLAG_ARRAY)
        {
            _PrintArray(fti, p, fti->size / fti->subscript, fti->subscript, 
                depth);
            PRINTF("\n");
        }
        else
        {
            _PrintScalar(fti, p, depth);
            PRINTF("\n");
        }
    }

    depth--;
    Iprintf(depth, "}");
}
#endif

#ifndef OE_BUILD_ENCLAVE
void OE_PrintStruct(
    const OE_StructTI* ti,
    const void* structIn)
{
    _PrintStruct(ti, structIn, 0);
    PRINTF("\n");
}
#endif

/*
**==============================================================================
**
** Lifetime management:
**
**==============================================================================
*/

static OE_Result _CopyStructs(
    const OE_StructTI* ti,
    const void* structIn,
    oe_size_t count,
    void* structOut,
    void* (alloc)(oe_size_t size))
{
    const oe_uint8_t* src = (oe_uint8_t*)structIn;
    oe_uint8_t* dest = (oe_uint8_t*)structOut;

    /* Copy construct each struct onto array memory */
    for (oe_size_t i = 0; i < count; i++)
    {
        OE_Result result;

        if ((result = OE_CopyStruct(ti, src, dest, alloc)) != OE_OK)
            return result;

        src += ti->size;
        dest += ti->size;
    }

    return OE_OK;
}

static OE_Result _ClonePtrField(
    const OE_StructTI* sti,
    const void* sin,
    const OE_FieldTI* fti,
    const void* ptrIn,
    void** ptrOut,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t count = 0;

    if (ptrOut)
        *ptrOut = OE_NULL;

    if (!sti || !sin || !fti || !ptrIn || !ptrOut || !alloc)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(_GetCount(sti, sin, fti, &count));

    if (fti->flags & OE_FLAG_STRING)
    {
        if (fti->type == OE_CHAR_T)
        {
            if (!(*ptrOut = _Strdup((char*)ptrIn, count, alloc)))
                OE_THROW(OE_OUT_OF_MEMORY);
        }
        else if (fti->type == OE_WCHAR_T)
        {
            if (!(*ptrOut = _Wcsdup((oe_wchar_t*)ptrIn, count, alloc)))
                OE_THROW(OE_OUT_OF_MEMORY);
        }
    }
    else if (fti->flags & OE_FLAG_COUNT)
    {
        oe_size_t size;

        /* Get the size of an element */
        size = _GetTypeSize(fti);

        /* Allocate enough memory to hold object(s) */
        if (!(*ptrOut = alloc(size * count)))
            OE_THROW(OE_OUT_OF_MEMORY);

        /* Clear output memory */
        MEMSET(*ptrOut, 0, size * count);

        /* Handle struct-pointers with [count] qualifier */
        if (fti->type == OE_STRUCT_T)
        {
            OE_TRY(_CopyStructs(fti->sti, ptrIn, count, *ptrOut, alloc));
        }
        else
        {
            MEMCPY(*ptrOut, ptrIn, size * count);
        }
    }
    else
    {
        /* ATTN: Handle other pointer types */
        OE_THROW(OE_UNEXPECTED);
    }

    result = OE_OK;

catch:

    if (result != OE_OK)
    {
        if (ptrOut && *ptrOut)
        {
            *ptrOut = OE_NULL;
        }
    }

    return result;
}

static OE_Result _CopyField(
    const OE_StructTI* sti,
    const void* sin,
    const OE_FieldTI* fti,
    const void* fin,
    void* fout,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;

    /* Check for null parameters */
    if (!fti || !fin || !fout|| !alloc)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Zero-initialize this field */
    MEMSET(fout, 0, fti->size);

    if (fti->flags & OE_FLAG_UNCHECKED)
    {
        /* Copy over [unchecked] field as-is */
        MEMCPY(fout, fin, fti->size);
    }
    else if (fti->flags & OE_FLAG_PTR)
    {
        const void* finp = *(const void**)fin;
        void* foutp = OE_NULL;

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
            MEMCPY(fout, fin, fti->size);
    }
    else /* scalar */
    {
        if (fti->type == OE_STRUCT_T)
            OE_TRY(OE_CopyStruct(fti->sti, fin, fout, alloc));
        else
            MEMCPY(fout, fin, fti->size);
    }

    result = OE_OK;

catch:
    
    return result;
}

static OE_Result _DestroyStructs(
    const OE_StructTI* sti,
    void* structs,
    oe_size_t count,
    OE_DeallocProc dealloc)
{
    OE_Result result = OE_UNEXPECTED;
    oe_uint8_t* p = (oe_uint8_t*)structs;

    if (!sti || !structs || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    for (oe_size_t i = 0; i < count; i++)
    {
        OE_TRY(OE_DestroyStruct(sti, p, dealloc));
        p += sti->size;
    }

    return OE_OK;

catch:

    return result;
}

OE_Result OE_CopyStruct(
    const OE_StructTI* sti,
    const void* sin,
    void* sout,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i;

    /* Check for null parameters */
    if (!sti || !sin || !sout || !alloc)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Zero-initialize destination structure */
    MEMSET(sout, 0, sti->size);

    /* For each field */
    for (i = 0; i < sti->nfields; i++)
    {
        const OE_FieldTI* fti = &sti->fields[i];
        const void* fin = (const oe_uint8_t*)sin + fti->offset;
        void* fout = (oe_uint8_t*)sout + fti->offset;
        OE_TRY(_CopyField(sti, sin, fti, fin, fout, alloc));
    }

    result = OE_OK;

catch:
    
    return result;
}

OE_Result OE_CloneStruct(
    const OE_StructTI* sti,
    const void* sin,
    void** sout,
    void* (alloc)(oe_size_t size))
{
    if (sout)
        *sout = OE_NULL;

    /* Check for null parameters */
    if (!sti || !sin || !alloc)
        return OE_INVALID_PARAMETER;

    /* Allocate new structure (allocate at least 1 byte) */
    if (!(*sout = alloc(sti->size > 0 ? sti->size : 1)))
        return OE_OUT_OF_MEMORY;

    return OE_CopyStruct(sti, sin, *sout, alloc);
}

static OE_Result _CloneStructs(
    const OE_StructTI* sti,
    const void* sin,
    oe_size_t count,
    void** sout,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;

    if (!sti || !sin || !count || !sout || !alloc)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!(*sout = alloc(sti->size * count)))
        return OE_OUT_OF_MEMORY;

    OE_TRY(_CopyStructs(sti, sin, count, *sout, alloc));

    result = OE_OK;

catch:
    return result;
}

static OE_Result _CloneBlob(
    const void* dataIn,
    oe_size_t size,
    void** dataOut,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;

    if (!dataIn || !size || !dataOut || !alloc)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!(*dataOut = alloc(size)))
        return OE_OUT_OF_MEMORY;

    MEMCPY(*dataOut, dataIn, size); 

    result = OE_OK;

catch:
    return result;
}

static OE_Result _ApplyStructPtrProc(
    const OE_StructTI* ti,
    void* strct,
    void (*proc)(void* ptr, oe_size_t size, void* procData),
    void* procData);

/* Apply the proc() function to every pointer within the struct array */
static OE_Result _ApplyStructsPtrProc(
    const OE_StructTI* ti,
    void* structs,
    oe_size_t count,
    void (*proc)(void* ptr, oe_size_t size, void* procData),
    void* procData)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i;

    for (i = 0; i < count; i++)
    {
        void* s = (oe_uint8_t*)structs + (i * ti->size);
        OE_TRY(_ApplyStructPtrProc(ti, s, proc, procData));
    }

    result = OE_OK;

catch:
    return result;
}

/* Apply the proc() function to every pointer within the struct */
static OE_Result _ApplyStructPtrProc(
    const OE_StructTI* ti,
    void* strct,
    void (*proc)(void* ptr, oe_size_t size, void* procData),
    void* procData)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i;

    if (!ti || !strct)
        OE_THROW(OE_INVALID_PARAMETER);


    /* For each field */
    for (i = 0; i < ti->nfields; i++)
    {
        const OE_FieldTI* fti = &ti->fields[i];
        oe_uint8_t* fptr = (oe_uint8_t*)strct + fti->offset;

        if (fti->flags & OE_FLAG_UNCHECKED)
        {
            /* Cannot release unchecked objects */
        }
        else if (fti->flags & OE_FLAG_PTR && fti->flags & OE_FLAG_ARRAY)
        {
            OE_THROW(OE_UNIMPLEMENTED);
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
                    /* ATTN: how do we get the oe_true size? */
                    oe_size_t bytes = _SizeofStr((const char*)ptr);
                    proc(ptr, bytes, procData);
                }
                else if (fti->type == OE_WCHAR_T)
                {
                    /* ATTN: how do we get the oe_true size? */
                    oe_size_t bytes = _SizeofWcs((const oe_wchar_t*)ptr);
                    proc(ptr, bytes, procData);
                }
            }
            else if (fti->flags & OE_FLAG_COUNT)
            {
                oe_size_t count;

                /* Get number of elements in this pointer array */
                OE_TRY(_GetCount(ti, strct, fti, &count));

                /* Handle struct-pointers with [count] qualifier */
                if (fti->type == OE_STRUCT_T)
                {
                    OE_TRY(_ApplyStructsPtrProc(
                        fti->sti, ptr, count, proc, procData));
                    proc(ptr, fti->sti->size * count, procData);
                }
                else
                {
                    oe_size_t size = _GetTypeSize(fti);
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
                OE_TRY(_ApplyStructsPtrProc(
                    fti->sti, fptr, fti->subscript, proc, procData));
            }
        }
        else /* scalar */
        {
            if (fti->type == OE_STRUCT_T)
            {
                OE_TRY(_ApplyStructPtrProc(
                    fti->sti, fptr, proc, procData));
            }
        }
    }


    result = OE_OK;

catch:
    return result;
}

static void _FreeProc(void* ptr, oe_size_t size, void* procData)
{
    OE_DeallocProc proc = (OE_DeallocProc)procData;

    if (proc)
        proc(ptr);
}

OE_Result OE_DestroyStruct(
    const OE_StructTI* ti,
    void* strct,
    OE_DeallocProc dealloc)
{
    OE_Result result = OE_UNEXPECTED;

    if (!ti || !strct || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(_ApplyStructPtrProc(ti, strct, _FreeProc, dealloc));

    MEMSET(strct, 0, ti->size);

    result = OE_OK;

catch:

    return result;
}

OE_Result OE_FreeStruct(
    const OE_StructTI* ti,
    void* strct,
    OE_DeallocProc dealloc)
{
    OE_Result result = OE_UNEXPECTED;

    if (!ti || !strct || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(OE_DestroyStruct(ti, strct, dealloc));
    dealloc(strct);

    result = OE_OK;

catch:
    return result;
}

OE_Result OE_ClearArg(
    const OE_StructTI* sti,
    void* sin,
    oe_size_t index,
    oe_bool isPtrPtr,
    void* arg,
    OE_DeallocProc dealloc)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_FieldTI* fti;
    oe_size_t count = 0;

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
        MEMSET(arg, 0, fti->size);
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
                    *(void**)arg = OE_NULL;
                }
                else if (fti->type == OE_WCHAR_T)
                {
                    dealloc(ptr);
                    *(void**)arg = OE_NULL;
                }
                else
                    OE_THROW(OE_UNEXPECTED);
            }
            else
            {
                if (!count)
                    OE_THROW(OE_UNEXPECTED);

                if (fti->type == OE_CHAR_T)
                    MEMSET(arg, 0, count * sizeof(char));
                else if (fti->type == OE_WCHAR_T)
                    MEMSET(arg, 0, count * sizeof(oe_wchar_t));
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
                    *(void**)arg = OE_NULL;
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
                    *(void**)arg = OE_NULL;
                }
                else
                {
                    if (!count)
                        OE_THROW(OE_UNEXPECTED);

                    MEMSET(arg, 0, _GetTypeSize(fti) * count);
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
                MEMSET(arg, 0, fti->subscript * sizeof(char));
            }
            else if (fti->type == OE_WCHAR_T)
            {
                MEMSET(arg, 0, fti->subscript * sizeof(oe_wchar_t));
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
            MEMSET(arg, 0, _GetTypeSize(fti) * fti->subscript);
        }
    }
    else /* scalar */
    {
        if (fti->type == OE_STRUCT_T)
            OE_TRY(_DestroyStructs(fti->sti, arg, 1, dealloc));
        else
            MEMSET(arg, 0, fti->size);
    }

    result = OE_OK;

catch:

    return result;
}

oe_size_t OE_StructFindField(
    const OE_StructTI* sti, 
    const char* name)
{
    if (!sti || !name)
        return (oe_size_t)-1;

    for (oe_size_t i = 0; i < sti->nfields; i++)
    {
        if (STRCMP(sti->fields[i].name, name) == 0)
            return i;
    }

    return (oe_size_t)-1;
}

OE_Result OE_ClearArgByName(
    const OE_StructTI* sti,
    void* strct,
    const char* name,
    oe_bool isPtrPtr,
    void* arg,
    OE_DeallocProc dealloc)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t index;

    if (!sti || !strct || !name || !arg || !dealloc)
        OE_THROW(OE_INVALID_PARAMETER);

    index = OE_StructFindField(sti, name);

    if (index == (oe_size_t)-1)
        OE_THROW(OE_NOT_FOUND);

    OE_TRY(OE_ClearArg(sti, strct, index, isPtrPtr, arg, dealloc));

    result = OE_OK;

catch:
    return result;
}

OE_Result OE_SetArg(
    const OE_StructTI* sti,
    void* sin,
    oe_size_t index,
    oe_bool isPtrPtr,
    void* arg,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;
    const OE_FieldTI* fti = OE_NULL;
    const void* field;
    oe_size_t count = 0;

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
    field = (oe_uint8_t*)sin + fti->offset;

    /* Get value of count field if any */
    if (fti->flags & OE_FLAG_COUNT)
        OE_TRY(_GetCount(sti, sin, fti, &count));

    if (fti->flags & OE_FLAG_UNCHECKED)
    {
        MEMCPY(arg, field, fti->size);
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
                else if (fti->type == OE_WCHAR_T)
                {
                    if (!(*app = _Wcsdup((const oe_wchar_t*)fp, count, alloc)))
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
                    MEMCPY(arg, fp, count * sizeof(char));
                else if (fti->type == OE_WCHAR_T)
                    MEMCPY(arg, fp, count * sizeof(oe_wchar_t));
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
                    oe_size_t size = _GetTypeSize(fti);
                    OE_TRY(_CloneBlob(fp, size * count, app, alloc));
                }
            }
            else
            {
                if (fti->type == OE_STRUCT_T)
                    OE_TRY(_CopyStructs(fti->sti, fp, count, arg, alloc));
                else
                {
                    oe_size_t size = _GetTypeSize(fti);
                    MEMCPY(arg, fp, size * count);
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
        oe_size_t count = fti->subscript;

        if (arg == field)
            OE_THROW(OE_OVERLAPPED_COPY);

        if (fti->flags & OE_FLAG_STRING)
        {
            if (fti->type == OE_CHAR_T)
                MEMCPY(arg, field, count * sizeof(char));
            else if (fti->type == OE_WCHAR_T)
                MEMCPY(arg, field, count * sizeof(oe_wchar_t));
            else
                OE_THROW(OE_UNEXPECTED);
        }
        else if (fti->type == OE_STRUCT_T)
            OE_TRY(_CopyStructs(fti->sti, field, count, arg, alloc));
        else
            MEMCPY(arg, field, fti->size);
    }
    else /* scalar */
    {
        if (arg == field)
            OE_THROW(OE_OVERLAPPED_COPY);

        if (fti->type == OE_STRUCT_T)
            OE_TRY(_CopyStructs(fti->sti, field, 1, arg, alloc));
        else
            MEMCPY(arg, field, fti->size);
    }

    result = OE_OK;

catch:

    return result;
}

OE_Result OE_InitArg(
    const OE_StructTI* sti,
    void* sin,
    oe_size_t index,
    oe_bool isPtrPtr,
    void* arg,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;
    const OE_FieldTI* fti = OE_NULL;
    oe_size_t count = 0;

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
        // MEMSET(arg, 0, fti->size);
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
                else if (fti->type == OE_WCHAR_T)
                {
                    if (!(*app = _Calloc(count * sizeof(oe_wchar_t), alloc)))
                        OE_THROW(OE_OUT_OF_MEMORY);
                }
                else
                    OE_THROW(OE_UNEXPECTED);
            }
            else
            {
                if (fti->type == OE_CHAR_T)
                    ; // MEMSET(arg, 0, count * sizeof(char));
                else if (fti->type == OE_WCHAR_T)
                    ; // MEMSET(arg, 0, count * sizeof(oe_wchar_t));
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
                ; // MEMSET(arg, 0, _GetTypeSize(fti) * count);
            }
        }
        else
        {
            OE_THROW(OE_UNEXPECTED);
        }
    }
    else if (fti->flags & OE_FLAG_ARRAY)
    {
        ; // MEMSET(arg, 0, fti->size);
    }
    else /* scalar */
    {
        ; // MEMSET(arg, 0, _GetTypeSize(fti));
    }

    result = OE_OK;

catch:

    return result;
}

OE_Result OE_SetArgByName(
    const OE_StructTI* sti,
    void* strct,
    const char* name,
    oe_bool isPtrPtr,
    void* arg,
    void* (alloc)(oe_size_t size))
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t index;

    if (!sti || !strct || !name || !arg)
        OE_THROW(OE_INVALID_PARAMETER);

    index = OE_StructFindField(sti, name);

    if (index == (oe_size_t)-1)
        OE_THROW(OE_NOT_FOUND);

    OE_TRY(OE_SetArg(sti, strct, index, isPtrPtr, arg, alloc));

    result = OE_OK;

catch:
    return result;
}

static OE_Result _CheckOptConstraint(
    const OE_StructTI* sti,
    const void* sin,
    const OE_FieldTI* fti)
{
    OE_Result result = OE_UNEXPECTED;
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
    fin = (const oe_uint8_t*)sin + fti->offset;

    /* If pointer at this address is null, then fail */
    if (!*(void**)fin)
        OE_THROW(OE_FAILED_OPT_CONSTRAINT);

    OE_THROW(OE_OK);

catch:
    return result;
}

OE_Result OE_CheckPreConstraints(
    const OE_StructTI* sti,
    const void* sin)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i;

    if (!sti || !sin)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        const OE_FieldTI* fti = &sti->fields[i];

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

catch:
    return result;
}

OE_Result OE_CheckPostConstraints(
    const OE_StructTI* sti,
    const void* sin)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i;

    if (!sti || !sin)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        const OE_FieldTI* fti = &sti->fields[i];

        if (!fti)
            OE_THROW(OE_UNEXPECTED);

        /* Check for missing [opt] constraint */
        if (!(fti->flags & OE_FLAG_OPT))
        {
            OE_TRY(_CheckOptConstraint(sti, sin, fti));
        }
    }

    OE_THROW(OE_OK);

catch:
    return result;
}

static OE_Result _TestOrFillPadding(
    const OE_StructTI* sti,
    const void* sin,
    oe_bool test, /* test if oe_true; fill sif oe_false */
    oe_uint8_t byte)
{
    OE_Result result = OE_UNEXPECTED;
    oe_size_t i = 0;

    if (!sti || !sin)
        OE_THROW(OE_INVALID_PARAMETER);

    for (i = 0; i < sti->nfields; i++)
    {
        const OE_FieldTI* fti = &sti->fields[i];
        void* fin;
        oe_uint8_t* start;
        oe_uint8_t* end;

        if (!fti)
            OE_THROW(OE_UNEXPECTED);

        /* Set 'fin' to point to this field */
        fin = (oe_uint8_t*)sin + fti->offset;

        /* Set 'start' to the end of this field */
        start = (oe_uint8_t*)fin + fti->size;

        /* Set 'end' to next field, else the end of structure */
        if (i + 1 != sti->nfields)
        {
            const OE_FieldTI* nfti = &sti->fields[i + 1];

            if (!nfti)
                OE_THROW(OE_UNEXPECTED);

            end = (oe_uint8_t*)sin + nfti->offset;
        }
        else
        {
            end = (oe_uint8_t*)sin + sti->size;
        }


        /* Test or fill the padding after this structure */
        while (start != end)
        {
            if (test)
            {
                if (*start++ != byte)
                    OE_THROW(OE_BUFFER_OVERRUN);
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
            oe_size_t n = 0;
            oe_uint8_t* p;

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

catch:
    return result;
}

OE_Result OE_TestStructPadding(
    const OE_StructTI* sti,
    const void* sin)
{
    return _TestOrFillPadding(sti, sin, oe_true, 0xAA);
}

OE_Result OE_PadStruct(
    const OE_StructTI* sti,
    const void* sin)
{
    return _TestOrFillPadding(sti, sin, oe_false, 0xAA);
}

static void _CheckProc(void* ptr, oe_size_t size, void* procData)
{
    oe_bool* flag = (oe_bool*)procData;

    if (__OE_GCheck(ptr) != 0)
    {
        __OE_GFix(ptr);

        if (flag)
            *flag = oe_false;
    }
}

OE_Result OE_CheckStruct(
    const OE_StructTI* ti,
    void* strct)
{
    oe_bool flag = oe_true;
    OE_Result result = OE_UNEXPECTED;

    if (!ti || !strct || !flag)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRY(OE_TestStructPadding(ti, strct));

    OE_TRY(_ApplyStructPtrProc(ti, strct, _CheckProc, &flag));

    if (!flag)
        OE_THROW(OE_BUFFER_OVERRUN);

    result = OE_OK;

catch:

    return result;
}
