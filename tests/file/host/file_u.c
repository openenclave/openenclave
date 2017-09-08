#include <openenclave/host.h>
#include "file_u.h"
#include "../types.h"

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

struct TestReadFileArgs
{
    int ret;
    unsigned char __pad1[4];
    const char *path;
    unsigned char __pad2[4];
    uint32_t *checksum;
    unsigned char __pad3[4];
};

extern const OE_StructTI TestReadFileArgs_ti;

static const OE_FieldTI _TestReadFileArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestReadFileArgs, ret),
        sizeof(int), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "path", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct TestReadFileArgs, path),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "checksum", /* name */
        OE_UINT32_T, /* type */
        NULL, /* structName */
        "1", /* countParam */
        OE_OFFSETOF(struct TestReadFileArgs, checksum),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI TestReadFileArgs_ti =
{
    0, /* flags */
    "TestReadFile", /* name */
    sizeof(struct TestReadFileArgs), /* size */
    _TestReadFileArgs_fields_ti, /* params */
    OE_COUNTOF(_TestReadFileArgs_fields_ti) /* nparams */
};

struct FopenArgs
{
    FILE *ret;
    unsigned char __pad1[4];
    const char *filename;
    unsigned char __pad2[4];
    const char *modes;
    unsigned char __pad3[4];
};

extern const OE_StructTI FopenArgs_ti;

static const OE_FieldTI _FopenArgs_fields_ti[] =
{
    {
        OE_FLAG_OCALL|OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "ret", /* name */
        OE_STRUCT_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct FopenArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "filename", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct FopenArgs, filename),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "modes", /* name */
        OE_CHAR_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct FopenArgs, modes),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI FopenArgs_ti =
{
    0, /* flags */
    "Fopen", /* name */
    sizeof(struct FopenArgs), /* size */
    _FopenArgs_fields_ti, /* params */
    OE_COUNTOF(_FopenArgs_fields_ti) /* nparams */
};

struct FreadArgs
{
    size_t ret;
    unsigned char __pad1[4];
    void *ptr;
    unsigned char __pad2[4];
    size_t size;
    unsigned char __pad3[4];
    FILE *stream;
    unsigned char __pad4[4];
};

extern const OE_StructTI FreadArgs_ti;

static const OE_FieldTI _FreadArgs_fields_ti[] =
{
    {
        OE_FLAG_OCALL, /* flags */
        "ret", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct FreadArgs, ret),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "ptr", /* name */
        OE_VOID_T, /* type */
        NULL, /* structName */
        "size", /* countParam */
        OE_OFFSETOF(struct FreadArgs, ptr),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "size", /* name */
        OE_SIZE_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct FreadArgs, size),
        sizeof(size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "stream", /* name */
        OE_STRUCT_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct FreadArgs, stream),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI FreadArgs_ti =
{
    0, /* flags */
    "Fread", /* name */
    sizeof(struct FreadArgs), /* size */
    _FreadArgs_fields_ti, /* params */
    OE_COUNTOF(_FreadArgs_fields_ti) /* nparams */
};

struct FcloseArgs
{
    int ret;
    unsigned char __pad1[4];
    FILE *stream;
    unsigned char __pad2[4];
};

extern const OE_StructTI FcloseArgs_ti;

static const OE_FieldTI _FcloseArgs_fields_ti[] =
{
    {
        OE_FLAG_OCALL, /* flags */
        "ret", /* name */
        OE_INT_T, /* type */
        NULL, /* structTI */
        NULL, /* countParam */
        OE_OFFSETOF(struct FcloseArgs, ret),
        sizeof(int), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "stream", /* name */
        OE_STRUCT_T, /* type */
        NULL, /* structName */
        NULL, /* countParam */
        OE_OFFSETOF(struct FcloseArgs, stream),
        sizeof(void*), /* size */
        0, /* subscript */
    },
};

const OE_StructTI FcloseArgs_ti =
{
    0, /* flags */
    "Fclose", /* name */
    sizeof(struct FcloseArgs), /* size */
    _FcloseArgs_fields_ti, /* params */
    OE_COUNTOF(_FcloseArgs_fields_ti) /* nparams */
};

/*
********************************************************************************
**
** Inbound calls
**
********************************************************************************
*/

OE_EXTERNC FILE *Fopen(
    const char *filename,
    const char *modes);

/* ICALL: generator.cpp(657) */
OE_OCALL void __Fopen(void* args)
{
    struct FopenArgs* __a = (struct FopenArgs*)args;

    __a->ret = Fopen(
        __a->filename,
        __a->modes);
}

OE_EXTERNC size_t Fread(
    void *ptr,
    size_t size,
    FILE *stream);

/* ICALL: generator.cpp(657) */
OE_OCALL void __Fread(void* args)
{
    struct FreadArgs* __a = (struct FreadArgs*)args;

    __a->ret = Fread(
        __a->ptr,
        __a->size,
        __a->stream);
}

OE_EXTERNC int Fclose(
    FILE *stream);

/* ICALL: generator.cpp(657) */
OE_OCALL void __Fclose(void* args)
{
    struct FcloseArgs* __a = (struct FcloseArgs*)args;

    __a->ret = Fclose(
        __a->stream);
}

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result TestReadFile(
    OE_Enclave* enclave,
    int *ret,
    const char *path,
    uint32_t *checksum)
{
    OE_Result __r = OE_UNEXPECTED;
    struct TestReadFileArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.path = path;
    __args.checksum = checksum;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__TestReadFile", &__args);
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

