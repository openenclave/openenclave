#include <openenclave.h>
#include "file_t.h"
#include "../types.h"

OE_INLINE void* _ConstMemcpy(
    const void* dest, 
    const void* src,
    oe_size_t n)
{
    return OE_Memcpy((void*)dest, src, n);
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
    oe_uint32_t *checksum;
    unsigned char __pad3[4];
};

extern const OE_StructTI TestReadFileArgs_ti;

static const OE_FieldTI _TestReadFileArgs_fields_ti[] =
{
    {
        OE_FLAG_ECALL, /* flags */
        "ret", /* name */
        OE_INT_T, /* type */
        OE_NULL, /* structTI */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct TestReadFileArgs, ret),
        sizeof(int), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "path", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct TestReadFileArgs, path),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "checksum", /* name */
        OE_UINT32_T, /* type */
        OE_NULL, /* structName */
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
        OE_NULL, /* structTI */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct FopenArgs, ret),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "filename", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct FopenArgs, filename),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "modes", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
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
    oe_size_t ret;
    unsigned char __pad1[4];
    void *ptr;
    unsigned char __pad2[4];
    oe_size_t size;
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
        OE_NULL, /* structTI */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct FreadArgs, ret),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_PTR|OE_FLAG_COUNT, /* flags */
        "ptr", /* name */
        OE_VOID_T, /* type */
        OE_NULL, /* structName */
        "size", /* countParam */
        OE_OFFSETOF(struct FreadArgs, ptr),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "size", /* name */
        OE_SIZE_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct FreadArgs, size),
        sizeof(oe_size_t), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "stream", /* name */
        OE_STRUCT_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
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
        OE_NULL, /* structTI */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct FcloseArgs, ret),
        sizeof(int), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_PTR|OE_FLAG_UNCHECKED, /* flags */
        "stream", /* name */
        OE_STRUCT_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
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

OE_EXTERNC int TestReadFile(
    const char *path,
    oe_uint32_t *checksum);

/* ICALL: generator.cpp(431) */
OE_ECALL void __TestReadFile(void* args)
{
    OE_Result __r = OE_OK;

    const OE_StructTI* __ti = &TestReadFileArgs_ti;
    typedef struct TestReadFileArgs __Args;
    __Args* __args = (__Args*)args;
    __Args __buf;
    __Args* __a = &__buf;

    OE_Memset(__a, 0, sizeof(__Args));

    __r = OE_CheckPreConstraints(__ti, args);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __args, 1, oe_true, (void*)&__a->path, OE_Malloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __args, 2, oe_true, (void*)&__a->checksum, OE_Malloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_PadStruct(__ti, __a);
    if (__r != OE_OK)
        goto done;

    __a->ret = TestReadFile(
        __a->path,
        __a->checksum);

    __r = OE_CheckStruct(__ti, __a);
    if (__r != OE_OK)
        goto done;


    __r = OE_SetArg(__ti, __a, 0, 0, &__args->ret, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_ClearArg(__ti, __a, 2, 0, __args->checksum, OE_HostFree);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __a, 2, 0, __args->checksum, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_CheckPostConstraints(__ti, args);
    if (__r != OE_OK)
        goto done;

done:
    OE_DestroyStruct(__ti, __a, OE_Free);

    (void)__r;
}

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

/* OCALL: generator.cpp(772) */
OE_EXTERNC OE_Result Fopen(
    FILE **ret,
    const char *filename,
    const char *modes)
{
    OE_Result __r = OE_UNEXPECTED;
    const OE_StructTI* __ti = &FopenArgs_ti;
    typedef struct FopenArgs __Args;
    __Args __args;
    __Args* __a = OE_NULL;

    /**************************/
    /*** create args struct ***/
    /**************************/

    OE_Memset(&__args, 0, sizeof(__Args));
    __args.filename = filename;
    __args.modes = modes;

    if (!(__a = (__Args*)OE_HostCalloc(1, sizeof(__Args))))
    {
        __r = OE_OUT_OF_MEMORY;
        goto done;
    }

    __r = OE_SetArg(__ti, &__args, 1, oe_true, (void*)&__a->filename, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, &__args, 2, oe_true, (void*)&__a->modes, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallHost("__Fopen", __a);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    __r = OE_SetArg(__ti, __a, 0, oe_true, ret, OE_Malloc);
    if (__r != OE_OK)
        goto done;

    /*************************/
    /*** output parameters ***/
    /*************************/

done:

    if (__a)
        OE_FreeStruct(__ti, __a, OE_HostFree);

    return __r;
}

/* OCALL: generator.cpp(772) */
OE_EXTERNC OE_Result Fread(
    oe_size_t *ret,
    void *ptr,
    oe_size_t size,
    FILE *stream)
{
    OE_Result __r = OE_UNEXPECTED;
    const OE_StructTI* __ti = &FreadArgs_ti;
    typedef struct FreadArgs __Args;
    __Args __args;
    __Args* __a = OE_NULL;

    /**************************/
    /*** create args struct ***/
    /**************************/

    OE_Memset(&__args, 0, sizeof(__Args));
    __args.ptr = ptr;
    __args.size = size;
    __args.stream = stream;

    if (!(__a = (__Args*)OE_HostCalloc(1, sizeof(__Args))))
    {
        __r = OE_OUT_OF_MEMORY;
        goto done;
    }

    __r = OE_SetArg(__ti, &__args, 1, oe_true, (void*)&__a->ptr, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, &__args, 2, oe_false, (void*)&__a->size, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, &__args, 3, oe_true, (void*)&__a->stream, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallHost("__Fread", __a);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    __r = OE_SetArg(__ti, __a, 0, 0, ret, OE_Malloc);
    if (__r != OE_OK)
        goto done;

    /*************************/
    /*** output parameters ***/
    /*************************/

    __r = OE_ClearArg(__ti, __a, 1, 0, ptr, OE_HostFree);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __a, 1, 0, ptr, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

done:

    if (__a)
        OE_FreeStruct(__ti, __a, OE_HostFree);

    return __r;
}

/* OCALL: generator.cpp(772) */
OE_EXTERNC OE_Result Fclose(
    int *ret,
    FILE *stream)
{
    OE_Result __r = OE_UNEXPECTED;
    const OE_StructTI* __ti = &FcloseArgs_ti;
    typedef struct FcloseArgs __Args;
    __Args __args;
    __Args* __a = OE_NULL;

    /**************************/
    /*** create args struct ***/
    /**************************/

    OE_Memset(&__args, 0, sizeof(__Args));
    __args.stream = stream;

    if (!(__a = (__Args*)OE_HostCalloc(1, sizeof(__Args))))
    {
        __r = OE_OUT_OF_MEMORY;
        goto done;
    }

    __r = OE_SetArg(__ti, &__args, 1, oe_true, (void*)&__a->stream, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallHost("__Fclose", __a);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    __r = OE_SetArg(__ti, __a, 0, 0, ret, OE_Malloc);
    if (__r != OE_OK)
        goto done;

    /*************************/
    /*** output parameters ***/
    /*************************/

done:

    if (__a)
        OE_FreeStruct(__ti, __a, OE_HostFree);

    return __r;
}

