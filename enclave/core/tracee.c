// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>

static oe_log_filter_t _active_log_filter = {0};
static char _enclave_filename[MAX_FILENAME_LEN];
static bool _debug_allowed_enclave = false;

const char* get_filename_from_path(const char* path)
{
    if (path)
    {
        for (size_t i = oe_strlen(path) - 1; i >= 0; i--)
        {
            if ((path[i] == '/') || (path[i] == '\\'))
            {
                return &path[i + 1];
            }
            else if (i == 0)
            {
                break;
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
#ifdef OE_USE_LIBSGX

#if defined(__linux__)
    oe_result_t result = 0;
    td_t* td = oe_get_td();
    uint8_t* report_buffer = NULL;

    if (td->simulate)
    {
        // enclave in simulate mode is treated as debug_allowed
        ret = true;
    }
    else
    {
        uint64_t report_buffer_size = OE_MAX_REPORT_SIZE;
        const sgx_report_t* sgx_report = NULL;
        oe_report_header_t* header = NULL;

        report_buffer = (uint8_t*)oe_malloc(OE_MAX_REPORT_SIZE);
        if (report_buffer == NULL)
            goto done;

        // get a report on the enclave itself for enclave identity information
        report_buffer_size = OE_MAX_REPORT_SIZE;
        result = oe_get_report(
            0, NULL, 0, NULL, 0, report_buffer, &report_buffer_size);
        if (result != OE_OK)
            goto done;

        header = (oe_report_header_t*)report_buffer;
        sgx_report = (const sgx_report_t*)header->report;
        ret = (sgx_report->body.attributes.flags & SGX_FLAGS_DEBUG) != 0;
    }
done:
    if (report_buffer)
        oe_free(report_buffer);
#elif defined(_WIN32)
    // WIN32 support is still under development.
    // We will have to come back to handle this case
    ret = true;
#endif

#else
// When adding support for non-SGX solutions, we need to find a way to correctly
// identify whether an enclave is debug-allowed.
#endif
    return ret;
}

/*
**==============================================================================
**
** _handle_oelog_init()
**
** Handle the OE_ECALL_LOG_INIT from host and initialize SDK logging
** configuration
**
**==============================================================================
*/
oe_result_t _handle_oelog_init(uint64_t arg)
{
    oe_result_t result = OE_FAILURE;
    const char* filename = NULL;
    oe_log_filter_t* filter = (oe_log_filter_t*)arg;
    oe_log_filter_t local;

    if (filter == NULL)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!oe_is_outside_enclave((void*)filter, sizeof(oe_log_filter_t)))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Copy structure into enclave memory */
    oe_secure_memcpy(&local, filter, sizeof(oe_log_filter_t));

    if (!oe_is_outside_enclave((void*)(local.path), local.path_len))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    oe_secure_memcpy(&_active_log_filter, &local, sizeof(oe_log_filter_t));
    filename = get_filename_from_path(_active_log_filter.path);
    if (filename)
    {
        oe_strlcpy(_enclave_filename, filename, sizeof(_enclave_filename));
    }
    else
    {
        oe_memset(_enclave_filename, 0, sizeof(_enclave_filename));
    }

    _debug_allowed_enclave = is_enclave_debug_allowed();
    result = OE_OK;
done:
    return result;
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
    if (level > _active_log_filter.level)
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
        (size_t)(OE_LOG_MESSAGE_LEN_MAX - bytes_written),
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
    return _active_log_filter.level;
}
