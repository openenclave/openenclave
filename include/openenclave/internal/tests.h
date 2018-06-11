// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TESTS_H
#define _OE_TESTS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#ifdef OE_BUILD_ENCLAVE
#define OE_PRINT OE_HostFprintf
#define OE_ABORT OE_Abort
#define STDERR 1
#else
#include <stdio.h>
#include <stdlib.h>
#define OE_PRINT fprintf
#define OE_ABORT abort
#define STDERR stderr
#endif

OE_EXTERNC_BEGIN

#define OE_TEST(COND)                           \
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
            OE_ABORT();                         \
        }                                       \
    } while (0)

/*
 * Return flags to pass to OE_CreateEnclave() based on the OE_SIMULATION
 * environment variable.
 */
uint32_t OE_GetCreateFlags(void);

OE_EXTERNC_END

#endif /* _OE_TESTS_H */
