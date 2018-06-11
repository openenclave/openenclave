// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TYPEINFO_H
#define _OE_TYPEINFO_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _OE_FieldTI OE_FieldTI;
typedef struct _OE_StructTI OE_StructTI;
typedef struct _OE_ParamTI OE_ParamTI;
typedef struct _OE_FunctionTI OE_FunctionTI;

// Type flags:
#define OE_FLAG_STRUCT (1 << 0)
#define OE_FLAG_CONST (1 << 1)
#define OE_FLAG_PTR (1 << 2)
#define OE_FLAG_ARRAY (1 << 3)

// Qualifier flags:
#define OE_FLAG_ECALL (1 << 5)
#define OE_FLAG_OCALL (1 << 6)
#define OE_FLAG_IN (1 << 7)
#define OE_FLAG_OUT (1 << 8)
#define OE_FLAG_REF (1 << 9)
#define OE_FLAG_UNCHECKED (1 << 10)
#define OE_FLAG_COUNT (1 << 11)
#define OE_FLAG_STRING (1 << 12)
#define OE_FLAG_OPT (1 << 13)

struct _OE_FieldTI
{
    /* flags (OE_FLAG_*) */
    uint32_t flags;

    /* Name of this field */
    const char* name;

    /* Type of field (OE_TYPE_*) */
    OE_Type type;

    /* Type information for this structure (when type==OE_STRUCT_TYPE) */
    const OE_StructTI* sti;

    /* For pointer types: the field in the struct that holds the array size */
    const char* countField;

    /* Offset of this field within struct */
    size_t offset;

    /* Size of this type */
    size_t size;

    /* Array subscript (when type==OE_FLAG_ARRAY) */
    int32_t subscript;
};

struct _OE_StructTI
{
    /* flags (OE_FLAG_*) */
    uint32_t flags;

    /* Name of this structure */
    const char* name;

    /* Size of this structure in bytes */
    size_t size;

    /* Pointer to array of fields */
    const OE_FieldTI* fields;

    /* Number of fields in the array */
    uint32_t nfields;
};

OE_Result OE_StructEq(
    const OE_StructTI* sti,
    const void* s1,
    const void* s2,
    bool* flag);

OE_Result OE_CopyStruct(
    const OE_StructTI* strucTI,
    const void* structIn,
    void* structOut,
    void*(alloc)(size_t size));

OE_Result OE_CloneStruct(
    const OE_StructTI* structTI,
    const void* structIn,
    void** structOut,
    void*(alloc)(size_t size));

void OE_PrintStruct(const OE_StructTI* structTI, const void* structIn);

OE_Result OE_DestroyStruct(
    const OE_StructTI* structTI,
    void* structPtr,
    OE_DeallocProc dealloc);

OE_Result OE_FreeStruct(
    const OE_StructTI* structTI,
    void* structPtr,
    OE_DeallocProc dealloc);

OE_Result OE_InitArg(
    const OE_StructTI* sti,
    void* strct,
    size_t index,
    bool isPtrPtr,
    void* arg,
    void*(alloc)(size_t size));

OE_Result OE_ClearArg(
    const OE_StructTI* sti,
    void* strct,
    size_t index,
    bool isPtrPtr,
    void* arg,
    OE_DeallocProc dealloc);

OE_Result OE_ClearArgByName(
    const OE_StructTI* sti,
    void* strct,
    const char* name,
    bool isPtrPtr,
    void* arg,
    OE_DeallocProc dealloc);

OE_Result OE_SetArg(
    const OE_StructTI* sti,
    void* strct,
    size_t index,
    bool isPtrPtr, /* if 'arg' is a pointer to a pointer to an object */
    void* arg,
    void*(alloc)(size_t size));

OE_Result OE_SetArgByName(
    const OE_StructTI* sti,
    void* strct,
    const char* name,
    bool isPtrPtr, /* if 'arg' is a pointer to a pointer to an object */
    void* arg,
    void*(alloc)(size_t size));

size_t OE_StructFindField(const OE_StructTI* structTI, const char* name);

OE_Result OE_CheckPreConstraints(const OE_StructTI* sti, const void* sin);

OE_Result OE_CheckPostConstraints(const OE_StructTI* sti, const void* sin);

OE_Result OE_TestStructPadding(const OE_StructTI* sti, const void* sin);

OE_Result OE_PadStruct(const OE_StructTI* sti, const void* sin);

OE_Result OE_CheckStruct(const OE_StructTI* ti, void* strct);

OE_EXTERNC_END

#endif /* _OE_TYPEINFO_H */
