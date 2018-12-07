// Copyright (c) Microsoft Corporation. All rights reserved.
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

OE_EXTERNC_BEGIN

#define OE_RAISE(RESULT)                                         \
    do                                                           \
    {                                                            \
        result = (RESULT);                                       \
        if (result != OE_OK)                                     \
        {                                                        \
            OE_TRACE_ERROR("Failed::%s", oe_result_str(result)); \
        }                                                        \
        goto done;                                               \
    } while (0)

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

OE_EXTERNC_END

#endif /* _OE_RAISE_H */
