// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TRACE_H
#define _OE_TRACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#define OE_PRINTF oe_host_printf
#else
#include <stdio.h>
#define OE_PRINTF printf
#endif

#define OE_TRACE_LEVEL_NONE 0
#define OE_TRACE_LEVEL_ERROR 1
#define OE_TRACE_LEVEL_INFO 2

OE_EXTERNC_BEGIN

OE_INLINE void __oe_trace_result(
    const char* op,
    oe_result_t result,
    const char* file,
    unsigned int line,
    const char* expr)
{
    if (result == OE_OK)
    {
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
        OE_PRINTF(
            "\nok: %s: %s(%u): result=%u: %s\n", op, file, line, result, expr);
#endif
    }
    else
    {
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_ERROR)
        OE_PRINTF(
            "\nfail: %s: %s(%u): result=%u: %s\n",
            op,
            file,
            line,
            result,
            expr);
#endif
    }
}

#ifdef __cplusplus
#define OE_CATCH _catch
#else
#define OE_CATCH catch
#endif

#define OE_THROW(RESULT)                                                 \
    do                                                                   \
    {                                                                    \
        result = (RESULT);                                               \
        __oe_trace_result("throw", result, __FILE__, __LINE__, #RESULT); \
        goto OE_CATCH;                                                   \
    } while (0)

#define OE_TRY(EXPR)                                                   \
    do                                                                 \
    {                                                                  \
        oe_result_t _result_ = (EXPR);                                 \
        __oe_trace_result("try", _result_, __FILE__, __LINE__, #EXPR); \
        if (_result_ != OE_OK)                                         \
        {                                                              \
            result = _result_;                                         \
            goto OE_CATCH;                                             \
        }                                                              \
    } while (0)

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_ERROR)
#define OE_TRACE_ERROR(...)     \
    do                          \
    {                           \
        OE_PRINTF(__VA_ARGS__); \
    } while (0)
#else
#define OE_TRACE_ERROR(...)
#endif

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
#define OE_TRACE_INFO(...)      \
    do                          \
    {                           \
        OE_PRINTF(__VA_ARGS__); \
    } while (0)
#else
#define OE_TRACE_INFO(...)
#endif

OE_EXTERNC_END

#endif /* _OE_TRACE_H */
