// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tracee.h"
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
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "core_t.h"

static oe_log_level_t _active_log_level = OE_LOG_LEVEL_ERROR;
static char _enclave_filename[OE_MAX_FILENAME_LEN];
static bool _debug_allowed_enclave = false;

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

    _debug_allowed_enclave = oe_is_enclave_debug_allowed();
}

oe_result_t oe_log(oe_log_level_t level, const char* fmt, ...)
{
    oe_result_t result = OE_FAILURE;
    oe_va_list ap;
    int n = 0;
    int bytes_written = 0;
    char* message = NULL;

    // skip logging for non-debug-allowed enclaves
    if (!_debug_allowed_enclave)
    {
        result = OE_OK;
        goto done;
    }

    // Check if this message should be skipped
    if (level > _active_log_level)
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

    if (!(message = oe_malloc(OE_LOG_MESSAGE_LEN_MAX)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    bytes_written =
        oe_snprintf(message, OE_LOG_MESSAGE_LEN_MAX, "%s:", _enclave_filename);

    if (bytes_written < 0)
        goto done;

    oe_va_start(ap, fmt);
    n = oe_vsnprintf(
        &message[bytes_written],
        OE_LOG_MESSAGE_LEN_MAX - (size_t)bytes_written,
        fmt,
        ap);
    oe_va_end(ap);

    if (n < 0)
        goto done;

    if (oe_log_ocall(level, message) != OE_OK)
        goto done;

    result = OE_OK;

done:

    if (message)
        oe_free(message);

    return result;
}

oe_log_level_t oe_get_current_logging_level(void)
{
    return _active_log_level;
}
