// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

typedef struct _args
{
    oe_result_t result;
    oe_enclave_t* enclave;
} args_t;

#endif /* _ARGS_H */
