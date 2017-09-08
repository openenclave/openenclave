#include <openenclave/host.h>
#include <stdlib.h>
#include "tester_u.h"
OE_INLINE void* _ConstMemcpy(
    const void* dest, 
    const void* src,
    size_t n)
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

extern const OE_StructTI Date_ti;

static const OE_FieldTI _Date_fields_ti[] =
{
    {
        0, /* flags */
        "mm", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countField */
        OE_OFFSETOF(struct Date, mm),
        sizeof(uint32_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "dd", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countField */
        OE_OFFSETOF(struct Date, dd),
        sizeof(uint32_t), /* size */
        0, /* subscript */
    },
    {
        0, /* flags */
        "yyyy", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countField */
        OE_OFFSETOF(struct Date, yyyy),
        sizeof(uint32_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI Date_ti =
{
    0, /* flags */
    "Date", /* name */
    sizeof(struct Date), /* size */
    _Date_fields_ti, /* fields */
    OE_COUNTOF(_Date_fields_ti) /* nfields */
};

extern const OE_StructTI Object_ti;

static const OE_FieldTI _Object_fields_ti[] =
{
    {
        0, /* flags */
        "id", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structTI */
        NULL, /* countField */
        OE_OFFSETOF(struct Object, id),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "name", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structTI */
        NULL, /* countField */
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

extern const OE_StructTI Node_ti;

static const OE_FieldTI _Node_fields_ti[] =
{
    {
        0, /* flags */
        "value", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countField */
        OE_OFFSETOF(struct Node, value),
        sizeof(uint32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "next", /* name */
        OE_STRUCT_T, /* type */
        &Node_ti, /* structTI */
        "1", /* countField */
        OE_OFFSETOF(struct Node, next),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI Node_ti =
{
    0, /* flags */
    "Node", /* name */
    sizeof(struct Node), /* size */
    _Node_fields_ti, /* fields */
    OE_COUNTOF(_Node_fields_ti) /* nfields */
};

struct ReturnVoidArgs
{
    unsigned char __pad0[4];
    int __dummy;
};

extern const OE_StructTI ReturnVoidArgs_ti;

static const OE_FieldTI _ReturnVoidArgs_fields_ti[] =
{
};

const OE_StructTI ReturnVoidArgs_ti =
{
    0, /* flags */
    "ReturnVoid", /* name */
    sizeof(struct ReturnVoidArgs), /* size */
    _ReturnVoidArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnVoidArgs_fields_ti) /* nparams */
};

struct ReturnUint32Args
{
    uint32_t ret;
    unsigned char __pad1[4];
};

extern const OE_StructTI ReturnUint32Args_ti;

static const OE_FieldTI _ReturnUint32Args_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct ReturnUint32Args, ret),
        sizeof(uint32_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnUint32Args_ti =
{
    0, /* flags */
    "ReturnUint32", /* name */
    sizeof(struct ReturnUint32Args), /* size */
    _ReturnUint32Args_fields_ti, /* params */
    OE_COUNTOF(_ReturnUint32Args_fields_ti) /* nparams */
};

struct ReturnStrArgs
{
    char *ret;
    unsigned char __pad1[4];
};

extern const OE_StructTI ReturnStrArgs_ti;

static const OE_FieldTI _ReturnStrArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "ret", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct ReturnStrArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnStrArgs_ti =
{
    0, /* flags */
    "ReturnStr", /* name */
    sizeof(struct ReturnStrArgs), /* size */
    _ReturnStrArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnStrArgs_fields_ti) /* nparams */
};

struct ReturnDateArgs
{
    struct Date ret;
    unsigned char __pad1[4];
};

extern const OE_StructTI ReturnDateArgs_ti;

static const OE_FieldTI _ReturnDateArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_STRUCT_T, /* type */
        &Date_ti, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct ReturnDateArgs, ret),
        sizeof(struct Date), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnDateArgs_ti =
{
    0, /* flags */
    "ReturnDate", /* name */
    sizeof(struct ReturnDateArgs), /* size */
    _ReturnDateArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnDateArgs_fields_ti) /* nparams */
};

struct ReturnObjectArgs
{
    struct Object ret;
    unsigned char __pad1[4];
};

extern const OE_StructTI ReturnObjectArgs_ti;

static const OE_FieldTI _ReturnObjectArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct ReturnObjectArgs, ret),
        sizeof(struct Object), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnObjectArgs_ti =
{
    0, /* flags */
    "ReturnObject", /* name */
    sizeof(struct ReturnObjectArgs), /* size */
    _ReturnObjectArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnObjectArgs_fields_ti) /* nparams */
};

struct ReturnObjectsArgs
{
    struct Object *ret;
    unsigned char __pad1[4];
    size_t count;
    unsigned char __pad2[4];
};

extern const OE_StructTI ReturnObjectsArgs_ti;

static const OE_FieldTI _ReturnObjectsArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "ret", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "count", /* countParam */
        OE_OFFSETOF(struct ReturnObjectsArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "count", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct ReturnObjectsArgs, count),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnObjectsArgs_ti =
{
    0, /* flags */
    "ReturnObjects", /* name */
    sizeof(struct ReturnObjectsArgs), /* size */
    _ReturnObjectsArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnObjectsArgs_fields_ti) /* nparams */
};

struct ReturnLinkedListArgs
{
    struct Node *ret;
    unsigned char __pad1[4];
};

extern const OE_StructTI ReturnLinkedListArgs_ti;

static const OE_FieldTI _ReturnLinkedListArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "ret", /* name */
        OE_STRUCT_T, /* type */
        &Node_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct ReturnLinkedListArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnLinkedListArgs_ti =
{
    0, /* flags */
    "ReturnLinkedList", /* name */
    sizeof(struct ReturnLinkedListArgs), /* size */
    _ReturnLinkedListArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnLinkedListArgs_fields_ti) /* nparams */
};

struct TestStrdupArgs
{
    char *ret;
    unsigned char __pad1[4];
    const char *s;
    unsigned char __pad2[4];
};

extern const OE_StructTI TestStrdupArgs_ti;

static const OE_FieldTI _TestStrdupArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "ret", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestStrdupArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "s", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestStrdupArgs, s),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TestStrdupArgs_ti =
{
    0, /* flags */
    "TestStrdup", /* name */
    sizeof(struct TestStrdupArgs), /* size */
    _TestStrdupArgs_fields_ti, /* params */
    OE_COUNTOF(_TestStrdupArgs_fields_ti) /* nparams */
};

struct CopyObjectArgs
{
    int32_t ret;
    unsigned char __pad1[4];
    struct Object *dest;
    unsigned char __pad2[4];
    const struct Object *src;
    unsigned char __pad3[4];
};

extern const OE_StructTI CopyObjectArgs_ti;

static const OE_FieldTI _CopyObjectArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct CopyObjectArgs, ret),
        sizeof(int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "dest", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct CopyObjectArgs, dest),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "src", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct CopyObjectArgs, src),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI CopyObjectArgs_ti =
{
    0, /* flags */
    "CopyObject", /* name */
    sizeof(struct CopyObjectArgs), /* size */
    _CopyObjectArgs_fields_ti, /* params */
    OE_COUNTOF(_CopyObjectArgs_fields_ti) /* nparams */
};

struct CopyObjectsArgs
{
    int32_t ret;
    unsigned char __pad1[4];
    struct Object dest[2];
    unsigned char __pad2[4];
    const struct Object src[2];
    unsigned char __pad3[4];
};

extern const OE_StructTI CopyObjectsArgs_ti;

static const OE_FieldTI _CopyObjectsArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct CopyObjectsArgs, ret),
        sizeof(int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_ARRAY, /* flags */
        "dest", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct CopyObjectsArgs, dest),
        sizeof(struct Object) * 2, /* size */
        2, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_ARRAY, /* flags */
        "src", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct CopyObjectsArgs, src),
        sizeof(struct Object) * 2, /* size */
        2, /* subscript */
    },
};

const OE_StructTI CopyObjectsArgs_ti =
{
    0, /* flags */
    "CopyObjects", /* name */
    sizeof(struct CopyObjectsArgs), /* size */
    _CopyObjectsArgs_fields_ti, /* params */
    OE_COUNTOF(_CopyObjectsArgs_fields_ti) /* nparams */
};

struct ECALL_MultipleParamsArgs
{
    int32_t ret;
    unsigned char __pad1[4];
    const char *strIn;
    unsigned char __pad2[4];
    uint32_t numIn;
    unsigned char __pad3[4];
    const struct Object *objectIn;
    unsigned char __pad4[4];
    char *strOut;
    unsigned char __pad5[4];
    uint32_t *numOut;
    unsigned char __pad6[4];
    struct Object *objectOut;
    unsigned char __pad7[4];
    struct Object *objectRefOut;
    unsigned char __pad8[4];
};

extern const OE_StructTI ECALL_MultipleParamsArgs_ti;

static const OE_FieldTI _ECALL_MultipleParamsArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, ret),
        sizeof(int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "strIn", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, strIn),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "numIn", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, numIn),
        sizeof(uint32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objectIn", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, objectIn),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_STRING, /* flags */
        "strOut", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        "128", /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, strOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "numOut", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structName */
        "1", /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, numOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objectOut", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, objectOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_REF|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objectRefOut", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct ECALL_MultipleParamsArgs, objectRefOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ECALL_MultipleParamsArgs_ti =
{
    0, /* flags */
    "ECALL_MultipleParams", /* name */
    sizeof(struct ECALL_MultipleParamsArgs), /* size */
    _ECALL_MultipleParamsArgs_fields_ti, /* params */
    OE_COUNTOF(_ECALL_MultipleParamsArgs_fields_ti) /* nparams */
};

struct OCALL_MultipleParamsArgs
{
    int32_t ret;
    unsigned char __pad1[4];
    const char *strIn;
    unsigned char __pad2[4];
    uint32_t numIn;
    unsigned char __pad3[4];
    const struct Object *objectIn;
    unsigned char __pad4[4];
    char *strOut;
    unsigned char __pad5[4];
    uint32_t *numOut;
    unsigned char __pad6[4];
    struct Object *objectOut;
    unsigned char __pad7[4];
    struct Object *objectRefOut;
    unsigned char __pad8[4];
};

extern const OE_StructTI OCALL_MultipleParamsArgs_ti;

static const OE_FieldTI _OCALL_MultipleParamsArgs_fields_ti[] =
{
    {
        OE_FLAG_OCALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, ret),
        sizeof(int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "strIn", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, strIn),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "numIn", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, numIn),
        sizeof(uint32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objectIn", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, objectIn),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_STRING, /* flags */
        "strOut", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        "128", /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, strOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "numOut", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structName */
        "1", /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, numOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objectOut", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, objectOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_REF|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "objectRefOut", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct OCALL_MultipleParamsArgs, objectRefOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI OCALL_MultipleParamsArgs_ti =
{
    0, /* flags */
    "OCALL_MultipleParams", /* name */
    sizeof(struct OCALL_MultipleParamsArgs), /* size */
    _OCALL_MultipleParamsArgs_fields_ti, /* params */
    OE_COUNTOF(_OCALL_MultipleParamsArgs_fields_ti) /* nparams */
};

struct GetObjectRefArgs
{
    int32_t ret;
    unsigned char __pad1[4];
    struct Object *object;
    unsigned char __pad2[4];
};

extern const OE_StructTI GetObjectRefArgs_ti;

static const OE_FieldTI _GetObjectRefArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct GetObjectRefArgs, ret),
        sizeof(int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_REF|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "object", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct GetObjectRefArgs, object),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI GetObjectRefArgs_ti =
{
    0, /* flags */
    "GetObjectRef", /* name */
    sizeof(struct GetObjectRefArgs), /* size */
    _GetObjectRefArgs_fields_ti, /* params */
    OE_COUNTOF(_GetObjectRefArgs_fields_ti) /* nparams */
};

struct ModifyObjectArgs
{
    int32_t ret;
    unsigned char __pad1[4];
    struct Object *object;
    unsigned char __pad2[4];
};

extern const OE_StructTI ModifyObjectArgs_ti;

static const OE_FieldTI _ModifyObjectArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT32_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct ModifyObjectArgs, ret),
        sizeof(int32_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "object", /* name */
        OE_STRUCT_T, /* type */
        &Object_ti, /* structTI */
        "1", /* countParam */
        OE_OFFSETOF(struct ModifyObjectArgs, object),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ModifyObjectArgs_ti =
{
    0, /* flags */
    "ModifyObject", /* name */
    sizeof(struct ModifyObjectArgs), /* size */
    _ModifyObjectArgs_fields_ti, /* params */
    OE_COUNTOF(_ModifyObjectArgs_fields_ti) /* nparams */
};

struct TestStrlcpyArgs
{
    size_t ret;
    unsigned char __pad1[4];
    char *dest;
    unsigned char __pad2[4];
    const char *src;
    unsigned char __pad3[4];
    size_t dsize;
    unsigned char __pad4[4];
};

extern const OE_StructTI TestStrlcpyArgs_ti;

static const OE_FieldTI _TestStrlcpyArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestStrlcpyArgs, ret),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_STRING, /* flags */
        "dest", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        "dsize", /* countParam */
        OE_OFFSETOF(struct TestStrlcpyArgs, dest),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "src", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestStrlcpyArgs, src),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "dsize", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestStrlcpyArgs, dsize),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TestStrlcpyArgs_ti =
{
    0, /* flags */
    "TestStrlcpy", /* name */
    sizeof(struct TestStrlcpyArgs), /* size */
    _TestStrlcpyArgs_fields_ti, /* params */
    OE_COUNTOF(_TestStrlcpyArgs_fields_ti) /* nparams */
};

struct TestOptQualifierArgs
{
    size_t ret;
    unsigned char __pad1[4];
    char *p1;
    unsigned char __pad2[4];
    const char *p2;
    unsigned char __pad3[4];
    size_t p1size;
    unsigned char __pad4[4];
};

extern const OE_StructTI TestOptQualifierArgs_ti;

static const OE_FieldTI _TestOptQualifierArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestOptQualifierArgs, ret),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_STRING|OE_FLAG_OPT, /* flags */
        "p1", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        "p1size", /* countParam */
        OE_OFFSETOF(struct TestOptQualifierArgs, p1),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING|OE_FLAG_OPT, /* flags */
        "p2", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestOptQualifierArgs, p2),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "p1size", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestOptQualifierArgs, p1size),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TestOptQualifierArgs_ti =
{
    0, /* flags */
    "TestOptQualifier", /* name */
    sizeof(struct TestOptQualifierArgs), /* size */
    _TestOptQualifierArgs_fields_ti, /* params */
    OE_COUNTOF(_TestOptQualifierArgs_fields_ti) /* nparams */
};

struct ReturnIntPtrArgs
{
    int *ret;
    unsigned char __pad1[4];
    int *p;
    unsigned char __pad2[4];
    size_t n;
    unsigned char __pad3[4];
};

extern const OE_StructTI ReturnIntPtrArgs_ti;

static const OE_FieldTI _ReturnIntPtrArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL|OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_OPT, /* flags */
        "ret", /* name */
        OE_INT_T, /* type */
        NULL, /* structTI */
        "n", /* countParam */
        OE_OFFSETOF(struct ReturnIntPtrArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT|OE_FLAG_OPT, /* flags */
        "p", /* name */
        OE_INT_T, /* type */
        NULL, /* structName */
        "n", /* countParam */
        OE_OFFSETOF(struct ReturnIntPtrArgs, p),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "n", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct ReturnIntPtrArgs, n),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnIntPtrArgs_ti =
{
    0, /* flags */
    "ReturnIntPtr", /* name */
    sizeof(struct ReturnIntPtrArgs), /* size */
    _ReturnIntPtrArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnIntPtrArgs_fields_ti) /* nparams */
};

struct TestCallbackArgs
{
    unsigned char __pad0[4];
    void *func;
    unsigned char __pad1[4];
};

extern const OE_StructTI TestCallbackArgs_ti;

static const OE_FieldTI _TestCallbackArgs_fields_ti[] =
{
    {
        OE_FLAG_IN|OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "func", /* name */
        OE_VOID_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestCallbackArgs, func),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TestCallbackArgs_ti =
{
    0, /* flags */
    "TestCallback", /* name */
    sizeof(struct TestCallbackArgs), /* size */
    _TestCallbackArgs_fields_ti, /* params */
    OE_COUNTOF(_TestCallbackArgs_fields_ti) /* nparams */
};

struct TestIntPtrRefArgs
{
    bool ret;
    unsigned char __pad1[4];
    int *intPtrOut;
    unsigned char __pad2[4];
    size_t n;
    unsigned char __pad3[4];
};

extern const OE_StructTI TestIntPtrRefArgs_ti;

static const OE_FieldTI _TestIntPtrRefArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_BOOL_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestIntPtrRefArgs, ret),
        sizeof(bool), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_OUT|OE_FLAG_REF|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "intPtrOut", /* name */
        OE_INT_T, /* type */
        NULL, /* structName */
        "n", /* countParam */
        OE_OFFSETOF(struct TestIntPtrRefArgs, intPtrOut),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "n", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestIntPtrRefArgs, n),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TestIntPtrRefArgs_ti =
{
    0, /* flags */
    "TestIntPtrRef", /* name */
    sizeof(struct TestIntPtrRefArgs), /* size */
    _TestIntPtrRefArgs_fields_ti, /* params */
    OE_COUNTOF(_TestIntPtrRefArgs_fields_ti) /* nparams */
};

struct TestBufferOverunArgs
{
    unsigned char __pad0[4];
    char src[8];
    unsigned char __pad1[4];
};

extern const OE_StructTI TestBufferOverunArgs_ti;

static const OE_FieldTI _TestBufferOverunArgs_fields_ti[] =
{
    {
        OE_FLAG_OUT|OE_FLAG_ARRAY, /* flags */
        "src", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestBufferOverunArgs, src),
        sizeof(char) * 8, /* size */
        8, /* subscript */
    },
};

const OE_StructTI TestBufferOverunArgs_ti =
{
    0, /* flags */
    "TestBufferOverun", /* name */
    sizeof(struct TestBufferOverunArgs), /* size */
    _TestBufferOverunArgs_fields_ti, /* params */
    OE_COUNTOF(_TestBufferOverunArgs_fields_ti) /* nparams */
};

struct ReturnEnclaveMemoryArgs
{
    void *ret;
    unsigned char __pad1[4];
};

extern const OE_StructTI ReturnEnclaveMemoryArgs_ti;

static const OE_FieldTI _ReturnEnclaveMemoryArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL|OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "ret", /* name */
        OE_VOID_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct ReturnEnclaveMemoryArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI ReturnEnclaveMemoryArgs_ti =
{
    0, /* flags */
    "ReturnEnclaveMemory", /* name */
    sizeof(struct ReturnEnclaveMemoryArgs), /* size */
    _ReturnEnclaveMemoryArgs_fields_ti, /* params */
    OE_COUNTOF(_ReturnEnclaveMemoryArgs_fields_ti) /* nparams */
};

struct TestBufferCopyArgs
{
    unsigned char __pad0[4];
    void *dest;
    unsigned char __pad1[4];
    const void *src;
    unsigned char __pad2[4];
    size_t n;
    unsigned char __pad3[4];
    bool forceOverwrite;
    unsigned char __pad4[4];
};

extern const OE_StructTI TestBufferCopyArgs_ti;

static const OE_FieldTI _TestBufferCopyArgs_fields_ti[] =
{
    {
        OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "dest", /* name */
        OE_VOID_T, /* type */
        NULL, /* structName */
        "n", /* countParam */
        OE_OFFSETOF(struct TestBufferCopyArgs, dest),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "src", /* name */
        OE_VOID_T, /* type */
        NULL, /* structName */
        "n", /* countParam */
        OE_OFFSETOF(struct TestBufferCopyArgs, src),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "n", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestBufferCopyArgs, n),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "forceOverwrite", /* name */
        OE_BOOL_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestBufferCopyArgs, forceOverwrite),
        sizeof(bool), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TestBufferCopyArgs_ti =
{
    0, /* flags */
    "TestBufferCopy", /* name */
    sizeof(struct TestBufferCopyArgs), /* size */
    _TestBufferCopyArgs_fields_ti, /* params */
    OE_COUNTOF(_TestBufferCopyArgs_fields_ti) /* nparams */
};

/*
********************************************************************************
**
** Inbound calls
**
********************************************************************************
*/

OE_EXTERNC int32_t OCALL_MultipleParams(
    const char *strIn,
    uint32_t numIn,
    const struct Object *objectIn,
    char *strOut,
    uint32_t *numOut,
    struct Object *objectOut,
    struct Object **objectRefOut);

/* ICALL: generator.cpp(657) */
OE_OCALL void __OCALL_MultipleParams(void* args)
{
    struct OCALL_MultipleParamsArgs* __a = (struct OCALL_MultipleParamsArgs*)args;

    __a->ret = OCALL_MultipleParams(
        __a->strIn,
        __a->numIn,
        __a->objectIn,
        __a->strOut,
        __a->numOut,
        __a->objectOut,
        &__a->objectRefOut);
}

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnVoid(    OE_Enclave* enclave)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnVoidArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnVoid", &__args);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    /*************************/
    /*** output parameters ***/
    /*************************/

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnUint32(
    OE_Enclave* enclave,
    uint32_t *ret)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnUint32Args __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnUint32", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnStr(
    OE_Enclave* enclave,
    char **ret)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnStrArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnStr", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnDate(
    OE_Enclave* enclave,
    struct Date *ret)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnDateArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnDate", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnObject(
    OE_Enclave* enclave,
    struct Object *ret)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnObjectArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnObject", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnObjects(
    OE_Enclave* enclave,
    struct Object **ret,
    size_t count)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnObjectsArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.count = count;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnObjects", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnLinkedList(
    OE_Enclave* enclave,
    struct Node **ret)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnLinkedListArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnLinkedList", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestStrdup(
    OE_Enclave* enclave,
    char **ret,
    const char *s)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestStrdupArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.s = s;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestStrdup", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result CopyObject(
    OE_Enclave* enclave,
    int32_t *ret,
    struct Object *dest,
    const struct Object *src)
{
    OE_Result __r = OE_UNEXPECTED;
    struct CopyObjectArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.dest = dest;
    __args.src = src;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__CopyObject", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result CopyObjects(
    OE_Enclave* enclave,
    int32_t *ret,
    struct Object dest[2],
    const struct Object src[2])
{
    OE_Result __r = OE_UNEXPECTED;
    struct CopyObjectsArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    _ConstMemcpy(__args.dest, dest, sizeof(__args.dest));
    _ConstMemcpy(__args.src, src, sizeof(__args.src));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__CopyObjects", &__args);
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

    memcpy(dest, __args.dest, sizeof(__args.dest));

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ECALL_MultipleParams(
    OE_Enclave* enclave,
    int32_t *ret,
    const char *strIn,
    uint32_t numIn,
    const struct Object *objectIn,
    char *strOut,
    uint32_t *numOut,
    struct Object *objectOut,
    struct Object **objectRefOut)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ECALL_MultipleParamsArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.strIn = strIn;
    __args.numIn = numIn;
    __args.objectIn = objectIn;
    __args.strOut = strOut;
    __args.numOut = numOut;
    __args.objectOut = objectOut;
    __args.objectRefOut = (void*)objectRefOut;


    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ECALL_MultipleParams", &__args);
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

    if (objectRefOut)
        *objectRefOut = __args.objectRefOut;

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result GetObjectRef(
    OE_Enclave* enclave,
    int32_t *ret,
    struct Object **object)
{
    OE_Result __r = OE_UNEXPECTED;
    struct GetObjectRefArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.object = (void*)object;


    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__GetObjectRef", &__args);
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

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ModifyObject(
    OE_Enclave* enclave,
    int32_t *ret,
    struct Object *object)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ModifyObjectArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.object = object;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ModifyObject", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestStrlcpy(
    OE_Enclave* enclave,
    size_t *ret,
    char *dest,
    const char *src,
    size_t dsize)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestStrlcpyArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.dest = dest;
    __args.src = src;
    __args.dsize = dsize;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestStrlcpy", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestOptQualifier(
    OE_Enclave* enclave,
    size_t *ret,
    char *p1,
    const char *p2,
    size_t p1size)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestOptQualifierArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.p1 = p1;
    __args.p2 = p2;
    __args.p1size = p1size;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestOptQualifier", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnIntPtr(
    OE_Enclave* enclave,
    int **ret,
    int *p,
    size_t n)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnIntPtrArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.p = p;
    __args.n = n;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnIntPtr", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestCallback(
    OE_Enclave* enclave,
    void *func)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestCallbackArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.func = func;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestCallback", &__args);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    /*************************/
    /*** output parameters ***/
    /*************************/

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestIntPtrRef(
    OE_Enclave* enclave,
    bool *ret,
    int **intPtrOut,
    size_t n)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestIntPtrRefArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.intPtrOut = (void*)intPtrOut;

    __args.n = n;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestIntPtrRef", &__args);
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

    if (intPtrOut)
        *intPtrOut = __args.intPtrOut;

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestBufferOverun(
    OE_Enclave* enclave,
    char src[8])
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestBufferOverunArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    _ConstMemcpy(__args.src, src, sizeof(__args.src));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestBufferOverun", &__args);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    /*************************/
    /*** output parameters ***/
    /*************************/

    memcpy(src, __args.src, sizeof(__args.src));

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result ReturnEnclaveMemory(
    OE_Enclave* enclave,
    void **ret)
{
    OE_Result __r = OE_UNEXPECTED;
    struct ReturnEnclaveMemoryArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__ReturnEnclaveMemory", &__args);
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

done:
    return __r;
}

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestBufferCopy(
    OE_Enclave* enclave,
    void *dest,
    const void *src,
    size_t n,
    bool forceOverwrite)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestBufferCopyArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.dest = dest;
    __args.src = src;
    __args.n = n;
    __args.forceOverwrite = forceOverwrite;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestBufferCopy", &__args);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    /*************************/
    /*** output parameters ***/
    /*************************/

done:
    return __r;
}

