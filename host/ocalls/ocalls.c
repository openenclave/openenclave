// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>

#include <openenclave/internal/trace.h>
#include "core_u.h"
#include "ocalls.h"

// Typically ocalls requiring less than this threshold are handled using
// the ocall buffer itself.
#define LARGE_ALLOCATION_THRESHOLD (16 * 1024)

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out)
{
    if (arg_out)
    {
        *arg_out = (uint64_t)malloc(arg_in);
        // Log only large allocations in INFO. Rest are logged to VERBOSE.
        if (arg_in < LARGE_ALLOCATION_THRESHOLD)
        {
            OE_TRACE_VERBOSE(
                "oe_host_malloc(%ld) called to allocate host memory.", arg_in);
        }
        else
        {
            OE_TRACE_INFO(
                "oe_host_malloc(%ld) called to allocate host memory.", arg_in);
        }
    }
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}
