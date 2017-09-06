#include <openenclave/host.h>
#include "pingpong_u.h"
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
    oe_uint64_t x;
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
        sizeof(oe_uint64_t), /* size */
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

OE_EXTERNC void Pong(
    const char *in,
    char out[128]);

/* ICALL: generator.cpp(657) */
OE_OCALL void __Pong(void* args)
{
    struct PongArgs* __a = (struct PongArgs*)args;

    Pong(
        __a->in,
        __a->out);
}

OE_EXTERNC void Log(
    const char *str,
    oe_uint64_t x);

/* ICALL: generator.cpp(657) */
OE_OCALL void __Log(void* args)
{
    struct LogArgs* __a = (struct LogArgs*)args;

    Log(
        __a->str,
        __a->x);
}

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

/* ECALL: generator.cpp(952) */
OE_EXTERNC OE_Result Ping(
    OE_Enclave* enclave,
    const char *in,
    char out[128])
{
    OE_Result __r = OE_UNEXPECTED;
    struct PingArgs __args;

    /**************************/
    /*** create args struct ***/
    /**************************/

    memset(&__args, 0, sizeof(__args));
    __args.in = in;
    _ConstMemcpy(__args.out, out, sizeof(__args.out));

    /********************/
    /*** perform call ***/
    /********************/

    __r = OE_CallEnclave(enclave, "__Ping", &__args);
    if (__r != OE_OK)
        goto done;

    /********************/
    /*** return value ***/
    /********************/

    /*************************/
    /*** output parameters ***/
    /*************************/

    memcpy(out, __args.out, sizeof(__args.out));

done:
    return __r;
}

