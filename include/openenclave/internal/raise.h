// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * \file raise.h
 *
 * This file defines macros to simplify functions that return oe_result_t.
 * For example, consider the following function definition.
 *
 *     oe_result_t Func1(const char* param)
 *     {
 *         oe_result_t result = OE_UNEXPECTED;
 *         oe_result_t r;
 *
 *         if (!param)
 *         {
 *             result = OE_INVALID_PARAMETER;
 *             goto done;
 *         }
 *
 *         r = Func2(param);
 *         if (r != OE_OK)
 *         {
 *             result = r;
 *             goto done;
 *         }
 *
 *         r = Func3(param);
 *         if (r != OE_OK)
 *         {
 *             result = r;
 *             goto done;
 *         }
 *
 *         result = OE_OK;
 *
 *     done:
 *         return result;
 *     }
 *
 * These macros can be used to simplify the function as follows.
 *
 *     oe_result_t Func1(const char* param)
 *     {
 *         oe_result_t result = OE_UNEXPECTED;
 *
 *         if (!param)
 *             OE_RAISE(OE_INVALID_PARAMETER);
 *
 *         OE_CHECK(Func2(param));
 *         OE_CHECK(Func3(param));
 *
 *         result = OE_OK;
 *
 *     done:
 *         return result;
 *     }
 *
 */

#ifndef _OE_RAISE_H
#define _OE_RAISE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/trace.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/corelibc/string.h>
#define _strcmp oe_strcmp
#else
#include <string.h>
#define _strcmp strcmp
#endif

OE_EXTERNC_BEGIN

#define OE_RAISE(RESULT, ...)                             \
    do                                                    \
    {                                                     \
        result = (RESULT);                                \
        if (result != OE_OK)                              \
        {                                                 \
            OE_TRACE_ERROR(":%s", oe_result_str(result)); \
        }                                                 \
        goto done;                                        \
    } while (0)

// Unlike gcc and clang, for pure C code, MSVC does not support ##__VA_ARGS__
// extension for getting rid of the trailing comma when empty args for variadic
// macros is detected. This will cause compilation error.
// To make OE code work on MSVC, you need to add NULL as the last parameter if
// variadic paramter is empty in OE_RAISE_MSG(RESULT, fmt, ...)
// eg : OE_RAISE_MSG(OE_FAILURE, "your message", NULL);

/* Note: on Linux, the above example fails, as the NULL pointer is fed as the
 * value for oe_result_t in log, showing invalid (null) output.
 *
 * A solution is to define OS specfic versions of OE_RAISE_MSG() that
 * handle cases with and without NULL, to work properly on all OSes while
 * avoiding the need to modify existing code.
 */

#if defined(_MSC_VER)
// For MSVC: add NULL if missing
#define OE_RAISE_MSG(RESULT, fmt, ...)                                     \
    do                                                                     \
    {                                                                      \
        result = (RESULT);                                                 \
        if (result != OE_OK)                                               \
        {                                                                  \
            if (!_strcmp(#__VA_ARGS__, ""))                                \
            {                                                              \
                OE_TRACE_ERROR(                                            \
                    fmt " (oe_result_t=%s)", NULL, oe_result_str(result)); \
            }                                                              \
            else                                                           \
            {                                                              \
                OE_TRACE_ERROR(                                            \
                    fmt " (oe_result_t=%s)",                               \
                    ##__VA_ARGS__,                                         \
                    oe_result_str(result));                                \
            }                                                              \
        }                                                                  \
        goto done;                                                         \
    } while (0)

#else
// For Linux etc.: remove NULL if present
#define OE_RAISE_MSG(RESULT, fmt, ...)                               \
    do                                                               \
    {                                                                \
        result = (RESULT);                                           \
        if (result != OE_OK)                                         \
        {                                                            \
            if (!_strcmp(#__VA_ARGS__, "NULL"))                      \
            {                                                        \
                OE_TRACE_ERROR(                                      \
                    fmt " (oe_result_t=%s)", oe_result_str(result)); \
            }                                                        \
            else                                                     \
            {                                                        \
                OE_TRACE_ERROR(                                      \
                    fmt " (oe_result_t=%s)",                         \
                    ##__VA_ARGS__,                                   \
                    oe_result_str(result));                          \
            }                                                        \
        }                                                            \
        goto done;                                                   \
    } while (0)

#endif

#define OE_RAISE_NO_TRACE(RESULT) \
    do                            \
    {                             \
        result = (RESULT);        \
        goto done;                \
    } while (0)

// This macro checks whether the expression argument evaluates to OE_OK. If not,
// call OE_RAISE
#define OE_CHECK(EXPRESSION)                 \
    do                                       \
    {                                        \
        oe_result_t _result_ = (EXPRESSION); \
        if (_result_ != OE_OK)               \
            OE_RAISE(_result_);              \
    } while (0)

#define OE_CHECK_NO_TRACE(EXPRESSION)        \
    do                                       \
    {                                        \
        oe_result_t _result_ = (EXPRESSION); \
        if (_result_ != OE_OK)               \
            OE_RAISE_NO_TRACE(_result_);     \
    } while (0)

#define OE_CHECK_MSG(EXPRESSION, fmt, ...)              \
    do                                                  \
    {                                                   \
        oe_result_t _result_ = (EXPRESSION);            \
        if (_result_ != OE_OK)                          \
            OE_RAISE_MSG(_result_, fmt, ##__VA_ARGS__); \
    } while (0)

OE_EXTERNC_END

#endif /* _OE_RAISE_H */
