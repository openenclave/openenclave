// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>

oe_result_t oe_send_log(const char* module, const char *fmt, ...)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_log_args_t* args = NULL;

    if (!module || !fmt)
        goto done;

    if (!(args = oe_host_malloc(sizeof(oe_log_args_t))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    if (oe_strncpy_s(
            args->module,
            sizeof(char) * OE_LOG_MODULE_LEN_MAX,
            module, oe_strlen(module)) != OE_OK)
        goto done;

    oe_va_list ap;
    oe_va_start(ap, fmt);
    int n = oe_vsnprintf(args->message, OE_LOG_MESSAGE_LEN_MAX, fmt, ap);
    oe_va_end(ap);

//TODO check n

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

char** oe_backtrace_symbols(void* const* buffer, int size)
{
    char** ret = NULL;
    oe_backtrace_symbols_args_t* args = NULL;

    if (!buffer || size > OE_BACKTRACE_MAX)
        goto done;

    if (!(args = oe_host_malloc(sizeof(oe_backtrace_symbols_args_t))))
        goto done;

    if (oe_memcpy_s(
            args->buffer,
            sizeof(void*) * OE_BACKTRACE_MAX,
            buffer,
            sizeof(void*) * size) != OE_OK)
        goto done;
    args->size = size;
    args->ret = NULL;

    if (oe_ocall(OE_OCALL_BACKTRACE_SYMBOLS, (uint64_t)args, NULL) != OE_OK)
        goto done;

    ret = args->ret;

done:

    if (args)
        oe_host_free(args);

    return ret;
}
