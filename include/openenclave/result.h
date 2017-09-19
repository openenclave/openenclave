/** 
 * \file result.h 
 *
 * This file defines OpenEnclave return codes (results).
 *
 */
#ifndef _OE_RESULT_H
#define _OE_RESULT_H

#include "defs.h"

OE_EXTERNC_BEGIN

/**
 * Result codes.
 */
typedef enum _OE_Result
{
    OE_OK,
    OE_FAILURE,
    OE_BUFFER_TOO_SMALL,
    OE_INVALID_PARAMETER,
    OE_OUT_OF_MEMORY,
    OE_OUT_OF_STACK,
    OE_OUT_OF_THREADS,
    OE_ECALL_FAILED,
    OE_OCALL_FAILED,
    OE_UNEXPECTED,
    OE_VERIFY_FAILED,
    OE_NOT_FOUND,
    OE_INTEGER_OVERFLOW,
    OE_WRONG_TYPE,
    OE_UNIMPLEMENTED,
    OE_OUT_OF_BOUNDS,
    OE_OVERLAPPED_COPY,
    OE_UNKNOWN_FUNCTION,
    OE_FAILED_OPT_CONSTRAINT,
    OE_DYNAMIC_LOAD_FAILED,
    OE_DYNAMIC_SYMBOL_LOOKUP_FAILED,
    OE_BUFFER_OVERRUN,
    OE_BAD_MAGIC,
    OE_IOCTL_FAILED,
    OE_UNSUPPORTED,
    OE_UNKNOWN_OPTION,
    OE_READ_FAILED,
    OE_OUT_OF_RANGE,
    OE_ALREADY_IN_USE,
    OE_SERVICE_UNAVAILABLE,
}
OE_Result;

/**
 * Retrieves a string for a result code.
 *
 * This function retrieves a string description for the given **result**
 * parameter.
 *
 * @param result Retrieve string description for this result code.
 *
 * @returns Returns a pointer to a static string description.
 *
 */
const char* OE_ResultStr(
    OE_Result result);

OE_INLINE void __OE_TraceThrow(
    OE_Result result,
    const char* file,
    unsigned int line,
    const char* expr)
{
    if (result == OE_OK)
    {
#if (OE_TRACE_LEVEL >= 2)
        printf(
            "\nok: throw: %s(%u): result=%u: %s\n", file, line, result, expr);
#endif
    }
    else
    {
#if (OE_TRACE_LEVEL >= 1)
        printf(
            "\nfail: throw: %s(%u): result=%u: %s\n", file, line, result, expr);
#endif
    }
}

#ifdef __cplusplus
# define OE_CATCH _catch
#else
# define OE_CATCH catch
#endif

OE_INLINE void __OE_TraceTry(
    OE_Result result,
    const char* file,
    unsigned int line,
    const char* expr)
{
    if (result == OE_OK)
    {
#if (OE_TRACE_LEVEL >= 2)
        printf(
            "\nok: try: %s(%u): result=%u: %s\n", file, line, result, expr);
#endif
    }
    else
    {
#if (OE_TRACE_LEVEL >= 1)
        printf(
            "\nfail: try: %s(%u): result=%u: %s\n", file, line, result, expr);
#endif
    }
}

#define OE_THROW(RESULT) \
    do \
    { \
        result = RESULT; \
        __OE_TraceThrow(result, __FILE__, __LINE__, #RESULT); \
        goto OE_CATCH; \
    } \
    while (0)

#define OE_TRY(EXPR) \
    do \
    { \
        __OE_TraceThrow(result = EXPR, __FILE__, __LINE__, #EXPR); \
        if (result != OE_OK) \
            goto OE_CATCH; \
    } \
    while (0)

OE_EXTERNC_END

#endif /* _OE_RESULT_H */
