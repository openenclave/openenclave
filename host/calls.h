// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/host.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include "hostthread.h"

#ifndef OE_HOST_CALLS_H
#define OE_HOST_CALLS_H

typedef struct _ocall_table
{
    const oe_ocall_func_t* ocalls;
    size_t num_ocalls;
} ocall_table_t;

extern ocall_table_t _ocall_tables[];

#endif /* OE_HOST_CALLS_H */
