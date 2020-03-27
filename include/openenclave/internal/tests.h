// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_TESTS_H
#define _OE_TESTS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#ifdef OE_BUILD_ENCLAVE
#include <openenclave/internal/print.h>
#define OE_PRINT oe_host_fprintf
#define OE_ABORT oe_abort
#define STDERR 1
#else
#include <stdio.h>
#include <stdlib.h>
#define OE_PRINT fprintf
#define OE_ABORT abort
#define STDERR stderr
#endif

OE_EXTERNC_BEGIN

#define OE_TEST_CODE_IF(EXP, CODE, OE_TEST_ABORT)   \
    do                                              \
    {                                               \
        oe_result_t _result_ = (EXP);               \
        oe_result_t _code_ = (CODE);                \
        if (_result_ != _code_)                     \
        {                                           \
            OE_PRINT(                               \
                STDERR,                             \
                "Test failed: %s(%u): %s %s!=%s\n", \
                __FILE__,                           \
                __LINE__,                           \
                __FUNCTION__,                       \
                oe_result_str(_result_),            \
                oe_result_str(_code_));             \
            if (OE_TEST_ABORT)                      \
                OE_ABORT();                         \
        }                                           \
    } while (0)

#define OE_TEST_CODE(EXP, CODE) OE_TEST_CODE_IF(EXP, CODE, true)

#define OE_TEST_CODE_IGNORE(EXP, CODE) OE_TEST_CODE_IF(EXP, CODE, false)

#define OE_TEST_IF(COND, OE_TEST_ABORT)         \
    do                                          \
    {                                           \
        if (!(COND))                            \
        {                                       \
            OE_PRINT(                           \
                STDERR,                         \
                "Test failed: %s(%u): %s %s\n", \
                __FILE__,                       \
                __LINE__,                       \
                __FUNCTION__,                   \
                #COND);                         \
            if (OE_TEST_ABORT)                  \
                OE_ABORT();                     \
        }                                       \
    } while (0)

#define OE_TEST(COND) OE_TEST_IF(COND, true)

#define OE_TEST_IGNORE(COND) OE_TEST_IF(COND, false)

/*
 * Return flags to pass to oe_create_enclave() based on the OE_SIMULATION
 * environment variable.
 */
uint32_t oe_get_create_flags(void);

OE_EXTERNC_END

#endif /* _OE_TESTS_H */
