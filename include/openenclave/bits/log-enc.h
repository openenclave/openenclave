// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef LOG_ENC_H
#define LOG_ENC_H

#include <openenclave/enclave.h>
#include <openenclave/bits/log-common.h>

OE_EXTERNC_BEGIN

#define oe_log_trace(module, fmt, ...) oe_log(LOG_TRACE, module, fmt, __VA_ARGS__)
#define oe_log_debug(module, fmt, ...) oe_log(LOG_DEBUG, module, fmt, __VA_ARGS__)
#define oe_log_info(module, fmt, ...)  oe_log(LOG_INFO,  module, fmt, __VA_ARGS__)
#define oe_log_warn(module, fmt, ...)  oe_log(LOG_WARN,  module, fmt, __VA_ARGS__)
#define oe_log_error(module, fmt, ...) oe_log(LOG_ERROR, module, fmt, __VA_ARGS__)

oe_result_t oe_log(uint8_t level, const char* module, const char* fmt, ...);

OE_EXTERNC_END

#endif /* LOG_ENC_H */
