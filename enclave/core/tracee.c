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
#include "tracee.h"

static oe_log_level_t _active_log_level = OE_LOG_LEVEL_ERROR;
static char _enclave_filename[OE_MAX_FILENAME_LEN];

const char* const oe_log_level_strings[OE_LOG_LEVEL_MAX] =
    {"NONE", "FATAL", "ERROR", "WARN", "INFO", "VERBOSE"};

static oe_mutex_t _log_lock = OE_MUTEX_INITIALIZER;

static oe_once_t _log_edger8r_once;

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

static void _log_edger8r_secure_unserialize(void)
{
    if (oe_edger8r_secure_unserialize)
        OE_TRACE_INFO(
            "The OCALL marshalling code will unserialize the non-deepycopy, "
            "out parameters within the enclave memory. "
            "To disable the feature, declare a STRONG "
            "oe_edger8r_secure_unserialize and set it to false");
    else
        OE_TRACE_INFO(
            "The OCALL marshalling code will unserialize the "
            "non-deepcopy, out parameters from the host memory, which does not "
            "mitigate against the xAPIC vulnerability. "
            "To enable in-enclave unserializing, declare a STRONG "
            "oe_edger8r_secure_unserialize and set it to true");
}

/*
**==============================================================================
**
** oe_log_init_ecall()
**
** Handle the OE_ECALL_LOG_INIT from host and initialize SDK logging
** configuration
**
** If enclave_path = NULL, then only the active log_level is modified.
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

    if (oe_mutex_lock(&_log_lock) != OE_OK)
        return;

    _active_log_level = (oe_log_level_t)log_level;

    if (enclave_path)
    {
        if ((filename = get_filename_from_path(enclave_path)))
        {
            oe_strlcpy(_enclave_filename, filename, sizeof(_enclave_filename));
        }
        else
        {
            memset(_enclave_filename, 0, sizeof(_enclave_filename));
        }
    }

    oe_mutex_unlock(&_log_lock);

    /* Log message for the edger8r secure_unserialize feature
     * (for xAPIC vulnerability mitigation) */
    oe_once(&_log_edger8r_once, _log_edger8r_secure_unserialize);
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
    bool locked = false;

    // Skip logging for non-debug-allowed enclaves
    if (!oe_is_enclave_debug_allowed())
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

    result = _log_enclave_message(level, _trace_buffer);

done:
    if (locked)
        oe_mutex_unlock(&_log_lock);

    return result;
}

oe_log_level_t oe_get_current_logging_level(void)
{
    return _active_log_level;
}
