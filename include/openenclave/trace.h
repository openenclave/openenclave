// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_TRACE_H
#define _OE_TRACE_H

#include <openenclave/log.h>
#include <time.h>

OE_EXTERNC_BEGIN

typedef void (*oe_log_callback_t)(
    void* context,
    bool is_enclave,
    const struct tm* t,
    long int usecs,
    oe_log_level_t level,
    uint64_t host_thread_id,
    const char* message);

oe_result_t oe_log_set_callback(void* context, oe_log_callback_t callback);

/// Host API to set host logging level verbosity dynamically.
oe_result_t oe_set_host_log_level(oe_log_level_t log_level);

/// Host API to set enclave logging level verbosity dynamically.
oe_result_t oe_set_enclave_log_level(oe_enclave_t* enclave, uint32_t log_level);

OE_EXTERNC_END

#endif
