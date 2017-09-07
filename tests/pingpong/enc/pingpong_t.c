#include <openenclave/enclave.h>
#include "pingpong_t.h"
OE_INLINE void* _ConstMemcpy(
    const void* dest, 
    const void* src,
    size_t n)
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

struct PingArgs
{
    unsigned char __pad0[4];
    const char *in;
    unsigned char __pad1[4];
    char out[128];
    unsigned char __pad2[4];
};

extern const OE_StructTI PingArgs_ti;

static const OE_FieldTI _PingArgs_fields_ti[] =
{
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "in", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct PingArgs, in),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_ARRAY|OE_FLAG_STRING, /* flags */
        "out", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct PingArgs, out),
        sizeof(char) * 128, /* size */
        128, /* subscript */
    },
};

const OE_StructTI PingArgs_ti =
{
    0, /* flags */
    "Ping", /* name */
    sizeof(struct PingArgs), /* size */
    _PingArgs_fields_ti, /* params */
    OE_COUNTOF(_PingArgs_fields_ti) /* nparams */
};

struct PongArgs
{
    unsigned char __pad0[4];
    const char *in;
    unsigned char __pad1[4];
    char out[128];
    unsigned char __pad2[4];
};

extern const OE_StructTI PongArgs_ti;

static const OE_FieldTI _PongArgs_fields_ti[] =
{
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "in", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct PongArgs, in),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN|OE_FLAG_OUT|OE_FLAG_ARRAY|OE_FLAG_STRING, /* flags */
        "out", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct PongArgs, out),
        sizeof(char) * 128, /* size */
        128, /* subscript */
    },
};

const OE_StructTI PongArgs_ti =
{
    0, /* flags */
    "Pong", /* name */
    sizeof(struct PongArgs), /* size */
    _PongArgs_fields_ti, /* params */
    OE_COUNTOF(_PongArgs_fields_ti) /* nparams */
};

struct LogArgs
{
    unsigned char __pad0[4];
    const char *str;
    unsigned char __pad1[4];
    uint64_t x;
    unsigned char __pad2[4];
};

extern const OE_StructTI LogArgs_ti;

static const OE_FieldTI _LogArgs_fields_ti[] =
{
    {
        OE_FLAG_IN|OE_FLAG_CONST|OE_FLAG_PTR|OE_FLAG_STRING, /* flags */
        "str", /* name */
        OE_CHAR_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct LogArgs, str),
        sizeof(void*), /* size */
        0, /* subscript */
    },
    {
        OE_FLAG_IN, /* flags */
        "x", /* name */
        OE_UINT64_T, /* type */
        OE_NULL, /* structName */
        OE_NULL, /* countParam */
        OE_OFFSETOF(struct LogArgs, x),
        sizeof(uint64_t), /* size */
        0, /* subscript */
    },
};

const OE_StructTI LogArgs_ti =
{
    0, /* flags */
    "Log", /* name */
    sizeof(struct LogArgs), /* size */
    _LogArgs_fields_ti, /* params */
    OE_COUNTOF(_LogArgs_fields_ti) /* nparams */
};

/*
********************************************************************************
**
** Inbound calls
**
********************************************************************************
*/

OE_EXTERNC void Ping(
    const char *in,
    char out[128]);

/* ICALL: generator.cpp(431) */
OE_ECALL void __Ping(void* args)
{
    OE_Result __r = OE_OK;

    const OE_StructTI* __ti = &PingArgs_ti;
    typedef struct PingArgs __Args;
    __Args* __args = (__Args*)args;
    __Args __buf;
    __Args* __a = &__buf;

    OE_Memset(__a, 0, sizeof(__Args));

    __r = OE_CheckPreConstraints(__ti, args);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __args, 0, true, (void*)&__a->in, OE_Malloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __args, 1, false, (void*)__a->out, OE_Malloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_PadStruct(__ti, __a);
    if (__r != OE_OK)
        goto done;

    Ping(
        __a->in,
        __a->out);

    __r = OE_CheckStruct(__ti, __a);
    if (__r != OE_OK)
        goto done;


    __r = OE_ClearArg(__ti, __a, 1, 0, __args->out, OE_HostFree);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __a, 1, 0, __args->out, OE_HostMalloc);
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
OE_EXTERNC OE_Result Pong(
    const char *in,
    char out[128])
{
    OE_Result __r = OE_UNEXPECTED;
    const OE_StructTI* __ti = &PongArgs_ti;
    typedef struct PongArgs __Args;
    __Args __args;
    __Args* __a = OE_NULL;

    /**************************/
    /*** create args struct ***/
    /**************************/

    OE_Memset(&__args, 0, sizeof(__Args));
    __args.in = in;
    _ConstMemcpy(__args.out, out, sizeof(__args.out));

    if (!(__a = (__Args*)OE_HostCalloc(1, sizeof(__Args))))
    {
        __r = OE_OUT_OF_MEMORY;
        goto done;
    }

    __r = OE_SetArg(__ti, &__args, 0, true, (void*)&__a->in, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, &__args, 1, false, (void*)__a->out, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallHost("__Pong", __a);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    /*************************/
    /*** output parameters ***/
    /*************************/

    __r = OE_ClearArg(__ti, __a, 1, 0, out, OE_HostFree);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, __a, 1, 0, out, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

done:

    if (__a)
        OE_FreeStruct(__ti, __a, OE_HostFree);

    return __r;
}

/* OCALL: generator.cpp(772) */
OE_EXTERNC OE_Result Log(
    const char *str,
    uint64_t x)
{
    OE_Result __r = OE_UNEXPECTED;
    const OE_StructTI* __ti = &LogArgs_ti;
    typedef struct LogArgs __Args;
    __Args __args;
    __Args* __a = OE_NULL;

    /**************************/
    /*** create args struct ***/
    /**************************/

    OE_Memset(&__args, 0, sizeof(__Args));
    __args.str = str;
    __args.x = x;

    if (!(__a = (__Args*)OE_HostCalloc(1, sizeof(__Args))))
    {
        __r = OE_OUT_OF_MEMORY;
        goto done;
    }

    __r = OE_SetArg(__ti, &__args, 0, true, (void*)&__a->str, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    __r = OE_SetArg(__ti, &__args, 1, false, (void*)&__a->x, OE_HostMalloc);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallHost("__Log", __a);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    /*************************/
    /*** output parameters ***/
    /*************************/

done:

    if (__a)
        OE_FreeStruct(__ti, __a, OE_HostFree);

    return __r;
}

