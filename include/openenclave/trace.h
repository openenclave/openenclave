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

OE_EXTERNC_END

#endif
