// Copyright (c) Open Enclave SDK contributors.
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

oe_result_t oe_handle_call_host_function(uint64_t arg, oe_enclave_t* enclave);

#endif /* OE_HOST_CALLS_H */
