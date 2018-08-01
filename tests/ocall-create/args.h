// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#include <openenclave/bits/types.h>

typedef struct _CreateEnclaveArgs
{
    const char* path;
    oe_enclave_type_t type;
    uint32_t flags;
    oe_enclave_t* enclave;
    oe_result_t ret;
} CreateEnclaveArgs;

typedef struct _CallEnclaveArgs
{
    oe_enclave_t* enclave;
    char* func;
    void* args;
    oe_result_t ret;
} CallEnclaveArgs;

typedef struct _TerminateEnclaveArgs
{
    oe_enclave_t* enclave;
    oe_result_t ret;
} TerminateEnclaveArgs;

typedef struct _TestEnclaveArgs
{
    const char* path;
    uint32_t flags;
    int ret;
} TestEnclaveArgs;

#endif /* _ARGS_H */
