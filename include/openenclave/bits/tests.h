// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TESTS_H
#define _OE_TESTS_H

#include <openenclave/defs.h>
#include <openenclave/types.h>
#ifdef OE_BUILD_ENCLAVE
#define OE_ABORT OE_Abort
#else
#include <stdio.h>
#include <stdlib.h>
#define OE_ABORT abort
#endif

OE_EXTERNC_BEGIN

#ifdef OE_BUILD_ENCLAVE
#define OE_TEST(COND)                           \
    do                                          \
    {                                           \
        if (!(COND))                            \
        {                                       \
            OE_HostPrintf(                      \
                "Test failed: %s(%u): %s %s\n", \
                __FILE__,                       \
                __LINE__,                       \
                __FUNCTION__,                   \
                #COND);                         \
            OE_ABORT();                         \
        }                                       \
    } while (0)

#else
#define OE_TEST(COND)                        \
    do                                       \
    {                                        \
        if (!(COND))                         \
        {                                    \
            fprintf(                         \
                stderr,                      \
                "Test failed: %s(%u): %s\n", \
                __FILE__,                    \
                __LINE__,                    \
                #COND);                      \
            OE_ABORT();                      \
        }                                    \
    } while (0)

#endif

/*
 * Return flags to pass to OE_CreateEnclave() based on the OE_SIMULATION
 * environment variable.
 */
uint32_t OE_GetCreateFlags(void);

OE_EXTERNC_END

#endif /* _OE_TESTS_H */
