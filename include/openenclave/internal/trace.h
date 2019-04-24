// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TRACE_H
#define _OE_TRACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

typedef enum _log_level_
{
    OE_LOG_LEVEL_NONE = 0,
    OE_LOG_LEVEL_FATAL,
    OE_LOG_LEVEL_ERROR,
    OE_LOG_LEVEL_WARNING,
    OE_LOG_LEVEL_INFO,
    OE_LOG_LEVEL_VERBOSE,
    OE_LOG_LEVEL_MAX
} log_level_t;

/* Maximum log length */
#define OE_LOG_MESSAGE_LEN_MAX 2048U
#define MAX_FILENAME_LEN 256U

typedef struct _oe_log_filter
{
    const char* path;
    uint64_t path_len;
    log_level_t level;
} oe_log_filter_t;

typedef struct _oe_log_args
{
    log_level_t level;
    char message[OE_LOG_MESSAGE_LEN_MAX];
} oe_log_args_t;

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
OE_EXTERNC_BEGIN
oe_result_t _handle_oelog_init(uint64_t arg);
oe_result_t oe_log(log_level_t level, const char* fmt, ...);
log_level_t get_current_logging_level(void);
OE_EXTERNC_END
#else
#include <stdio.h>
OE_EXTERNC_BEGIN
oe_result_t oe_log_enclave_init(oe_enclave_t* enclave);
void oe_log(log_level_t level, const char* fmt, ...);
log_level_t get_current_logging_level(void);
void log_message(bool is_enclave, oe_log_args_t* args);
OE_EXTERNC_END
#endif

#define OE_TRACE(level, ...)        \
    do                              \
    {                               \
        oe_log(level, __VA_ARGS__); \
    } while (0)

#define OE_TRACE_FATAL(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_FATAL,      \
        fmt "[%s %s:%d]\n",      \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_ERROR(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_ERROR,      \
        fmt "[%s %s:%d]\n",      \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_WARNING(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_WARNING,      \
        fmt "[%s %s:%d]\n",        \
        ##__VA_ARGS__,             \
        __FILE__,                  \
        __FUNCTION__,              \
        __LINE__)

#define OE_TRACE_INFO(fmt, ...) \
    OE_TRACE(                   \
        OE_LOG_LEVEL_INFO,      \
        fmt "[%s %s:%d]\n",     \
        ##__VA_ARGS__,          \
        __FILE__,               \
        __FUNCTION__,           \
        __LINE__)

#define OE_TRACE_VERBOSE(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_VERBOSE,      \
        fmt "[%s %s:%d]\n",        \
        ##__VA_ARGS__,             \
        __FILE__,                  \
        __FUNCTION__,              \
        __LINE__)

#endif
