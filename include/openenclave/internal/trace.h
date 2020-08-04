// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_TRACE_H
#define _OE_TRACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef enum _oe_log_level
{
    OE_LOG_LEVEL_NONE = 0,
    OE_LOG_LEVEL_FATAL,
    OE_LOG_LEVEL_ERROR,
    OE_LOG_LEVEL_WARNING,
    OE_LOG_LEVEL_INFO,
    OE_LOG_LEVEL_VERBOSE,
    OE_LOG_LEVEL_MAX
} oe_log_level_t;

extern oe_log_level_t _log_level;

/* Maximum log length */
#define OE_LOG_MESSAGE_LEN_MAX 2048U
#define OE_MAX_FILENAME_LEN 256U

#if !defined(OE_BUILD_ENCLAVE)
typedef void (*oe_log_callback_t)(
    void* context,
    bool is_enclave,
    const char* time,
    long int usecs,
    oe_log_level_t level,
    uint64_t host_thread_id,
    const char* message);
oe_result_t oe_log_set_callback(void* context, oe_log_callback_t callback);
extern void* oe_log_context;
extern oe_log_callback_t oe_log_callback;

oe_result_t oe_log_enclave_init(oe_enclave_t* enclave);
void oe_log_message(bool is_enclave, oe_log_level_t level, const char* message);
#endif

oe_result_t oe_log(oe_log_level_t level, const char* fmt, ...);
oe_log_level_t oe_get_current_logging_level(void);
void initialize_log_config(void);

#define OE_TRACE(level, ...)        \
    do                              \
    {                               \
        oe_log(level, __VA_ARGS__); \
    } while (0)

#define OE_TRACE_FATAL(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_FATAL,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_ERROR(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_ERROR,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_WARNING(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_WARNING,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        __FILE__,                  \
        __FUNCTION__,              \
        __LINE__)

#define OE_TRACE_INFO(fmt, ...) \
    OE_TRACE(                   \
        OE_LOG_LEVEL_INFO,      \
        fmt " [%s:%s:%d]\n",    \
        ##__VA_ARGS__,          \
        __FILE__,               \
        __FUNCTION__,           \
        __LINE__)

#define OE_TRACE_VERBOSE(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_VERBOSE,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        __FILE__,                  \
        __FUNCTION__,              \
        __LINE__)

OE_EXTERNC_END

#endif
