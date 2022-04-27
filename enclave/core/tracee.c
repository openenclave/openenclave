// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <openenclave/tracee.h>

#include "core_t.h"
#include "openenclave/log.h"
#include "platform_t.h"
#include "tracee.h"

static oe_log_level_t _active_log_level = OE_LOG_LEVEL_ERROR;
static char _enclave_filename[OE_MAX_FILENAME_LEN];

const char* const oe_log_level_strings[OE_LOG_LEVEL_MAX] =
    {"NONE", "FATAL", "ERROR", "WARN", "INFO", "VERBOSE"};

static oe_mutex_t _log_lock = OE_MUTEX_INITIALIZER;

const char* get_filename_from_path(const char* path)
{
    if (path)
    {
        size_t path_len = oe_strlen(path);

        for (size_t i = path_len; i > 0; i--)
        {
            if ((path[i - 1] == '/') || (path[i - 1] == '\\'))
            {
                return &path[i];
            }
        }
    }
    return path;
}

/*
**==============================================================================
**
** oe_log_init_ecall()
**
** Handle the OE_ECALL_LOG_INIT from host and initialize SDK logging
** configuration
**
**==============================================================================
*/

void oe_log_init_ecall(const char* enclave_path, uint32_t log_level)
{
    const char* filename;

    // Returning OE_UNSUPPORTED means that the logging.edl is not properly
    // imported. Do not perform the initialization in this case.
    if (oe_log_is_supported_ocall() == OE_UNSUPPORTED)
        return;

    _active_log_level = (oe_log_level_t)log_level;

    if ((filename = get_filename_from_path(enclave_path)))
    {
        oe_strlcpy(_enclave_filename, filename, sizeof(_enclave_filename));
    }
    else
    {
        memset(_enclave_filename, 0, sizeof(_enclave_filename));
    }
}

static void* _enclave_log_context = NULL;
static oe_enclave_log_callback_t _enclave_log_callback = NULL;
static char _trace_buffer[OE_LOG_MESSAGE_LEN_MAX];

oe_result_t oe_enclave_log_set_callback(
    void* context,
    oe_enclave_log_callback_t callback)
{
    oe_result_t result = OE_OK;

    OE_CHECK_NO_TRACE(oe_mutex_lock(&_log_lock));

    _enclave_log_context = context;
    _enclave_log_callback = callback;
    oe_mutex_unlock(&_log_lock);

    /* This trace call does not introduce recursive calls. */
    OE_TRACE_INFO("enclave logging callback is set");

done:
    return result;
}

static oe_result_t _log_enclave_message(
    oe_log_level_t level,
    const char* message)
{
    oe_result_t result = OE_FAILURE;

    if (!message)
        OE_RAISE_NO_TRACE(OE_UNEXPECTED);

    if (_enclave_log_callback)
    {
        (_enclave_log_callback)(
            _enclave_log_context, level, (uint64_t)oe_thread_self(), message);
    }
    else
    {
        // Check if this message should be skipped
        if (level > _active_log_level)
        {
            result = OE_OK;
            goto done;
        }

        if ((result = oe_log_ocall(level, message)) != OE_OK)
            goto done;

#if defined(__x86_64__) || defined(_M_X64)
        if (result == OE_OK)
        {
            if (level == OE_LOG_LEVEL_ERROR || level == OE_LOG_LEVEL_FATAL)
            {
                // Fetch current values of FS and GS. Typically, FS[0] == FS and
                // GS[0] == GS.
                uint64_t fs;
                uint64_t gs;
                asm volatile("mov %%fs:0, %0" : "=r"(fs));
                asm volatile("mov %%gs:0, %0" : "=r"(gs));

                // We can make ocalls only if td has been initialized which is
                // true only when the self-pointer has been setup (non-zero).
                if (gs)
                {
                    // Restore FS if FS has been modified.
                    if (fs != gs)
                    {
                        // wrfsbase could trigger an exception. The enclave may
                        // not be in a state to emulate the instruction.
                        // Therefore, just restore FS[0].
                        asm volatile("mov %0, %%fs:0" : : "r"(gs) : "memory");
                    }

                    void* buffer[OE_BACKTRACE_MAX];
                    int size;
                    oe_result_t r = OE_UNEXPECTED;
                    if ((size = oe_backtrace(buffer, OE_BACKTRACE_MAX)) > 0)
                    {
                        oe_sgx_log_backtrace_ocall(
                            &r,
                            oe_get_enclave(),
                            (uint64_t*)buffer,
                            (size_t)size);
                    }
                    else
                    {
                        // It is not possible to convey much information at this
                        // point.
                    }

                    // Rever FS if it was restored above.
                    if (fs != gs)
                        asm volatile("mov %0, %%fs:0" : : "r"(fs) : "memory");
                }
            }
        }
#endif
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_log(oe_log_level_t level, const char* fmt, ...)
{
    oe_result_t result = OE_FAILURE;
    oe_va_list ap;
    int n = 0;
    int bytes_written = 0;
    char* message = NULL;
    bool locked = false;

    // Skip logging for non-debug-allowed enclaves
    if (!is_enclave_debug_allowed())
    {
        result = OE_OK;
        goto done;
    }

    // Validate input
    if (!fmt)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    // Take the log file lock.
    OE_CHECK_NO_TRACE(oe_mutex_lock(&_log_lock));
    locked = true;

    bytes_written = oe_snprintf(
        _trace_buffer, OE_LOG_MESSAGE_LEN_MAX, "%s:", _enclave_filename);

    if (bytes_written < 0)
        goto done;

    oe_va_start(ap, fmt);
    n = oe_vsnprintf(
        &_trace_buffer[bytes_written],
        OE_LOG_MESSAGE_LEN_MAX - (size_t)bytes_written,
        fmt,
        ap);
    oe_va_end(ap);

    if (n < 0)
        goto done;

    result = _log_enclave_message(level, message);

done:
    if (locked)
        oe_mutex_unlock(&_log_lock);

    return result;
}

oe_log_level_t oe_get_current_logging_level(void)
{
    return _active_log_level;
}
