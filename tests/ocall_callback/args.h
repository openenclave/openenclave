// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ocall_callback_args_h
#define _ocall_callback_args_h

#include <openenclave/internal/calls.h>
#include <openenclave/internal/sgxtypes.h>

typedef struct _test_callback_args
{
    void (*callback)(void* arg, oe_enclave_t* enclave);
    uint64_t in;
    uint64_t out;
} test_callback_args_t;

#endif /* _ocall_callback_args_h */
