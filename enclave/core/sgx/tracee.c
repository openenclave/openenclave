// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "report.h"

static log_level_t _active_log_level = OE_LOG_LEVEL_ERROR;
static char _enclave_filename[MAX_FILENAME_LEN];
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

// Read an enclave's identity attribute to see to if it was signed as an debug
// enclave
bool is_enclave_debug_allowed()
{
    bool ret = false;
    td_t* td = oe_get_td();

    if (td->simulate)
    {
        // enclave in simulate mode is treated as debug_allowed
        ret = true;
    }
    else
    {
        // get a report on the enclave itself for enclave identity information
        sgx_report_t sgx_report;
        oe_result_t result = sgx_create_report(NULL, 0, NULL, 0, &sgx_report);
        if (result != OE_OK)
            goto done;

        ret = (sgx_report.body.attributes.flags & SGX_FLAGS_DEBUG) != 0;
    }
done:
    return ret;
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

void oe_log_init_ecall(const char* enclave_path, uint64_t log_level)
{
    const char* filename;

    _active_log_level = (log_level_t)log_level;

    if ((filename = get_filename_from_path(enclave_path)))
    {
        oe_strlcpy(_enclave_filename, filename, sizeof(_enclave_filename));
    }
    else
    {
        memset(_enclave_filename, 0, sizeof(_enclave_filename));
    }

    _debug_allowed_enclave = is_enclave_debug_allowed();
}

oe_result_t oe_log(log_level_t level, const char* fmt, ...)
{
    oe_result_t result = OE_FAILURE;
    oe_log_args_t* args = NULL;
    oe_va_list ap;
    int n = 0;
    int bytes_written = 0;

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

    // Prepare a log record for sending to the host for logging
    if (!(args = oe_host_malloc(sizeof(oe_log_args_t))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    bytes_written = oe_snprintf(
        args->message, OE_LOG_MESSAGE_LEN_MAX, "%s:", _enclave_filename);

    if (bytes_written < 0)
        goto done;

    args->level = level;
    oe_va_start(ap, fmt);
    n = oe_vsnprintf(
        &args->message[bytes_written],
        OE_LOG_MESSAGE_LEN_MAX - (size_t)bytes_written,
        fmt,
        ap);
    oe_va_end(ap);

    if (n < 0)
        goto done;

    // send over to the host
    if (oe_ocall(OE_OCALL_LOG, (uint64_t)args, NULL) != OE_OK)
        goto done;

    result = OE_OK;
done:
    if (args)
    {
        oe_host_free(args);
    }
    return result;
}

log_level_t get_current_logging_level(void)
{
    return _active_log_level;
}
