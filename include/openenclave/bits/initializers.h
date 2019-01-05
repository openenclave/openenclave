// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file initializers.h
 *
 * This file defines data structures to set up Enclave Initializers.
 *
 */
#ifndef _OE_BITS_INITIALIZERS_H
#define _OE_BITS_INITIALIZERS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _enclave_initializer
{
    const char* group_name;
    void (*initializer)(void);
    bool executed;
} oe_enclave_initializer_t;

#define __OE_JOIN1(a, b) a##b
#define __OE_JOIN(a, b) __OE_JOIN1(a, b)

#define OE_REGISTER_ENCLAVE_INITIALIZER(GROUP_NAME, INITIALIZER)            \
    __attribute__(                                                          \
        (used, section("_oeinitializers"))) static oe_enclave_initializer_t \
        __OE_JOIN(einitializer, __LINE__) = {GROUP_NAME, INITIALIZER, false}

void oe_call_initializer_group(const char* group_name);

OE_EXTERNC_END

#endif // _OE_BITS_INITIALIZERS_H
