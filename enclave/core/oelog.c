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
#include <openenclave/internal/oelog-enclave.h>
#include "oelog.h"

static uint8_t log_level = OE_LOG_NONE;

void oe_log_init(uint64_t level) {
    log_level = (log_level_t)level;
}

oe_result_t oe_log(log_level_t level, const char* module, const char *fmt, ...)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_log_args_t* args = NULL;

    if (!module || !fmt)
        goto done;

    if (level < log_level)
        goto done;

    if (!(args = oe_host_malloc(sizeof(oe_log_args_t))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    args->level = level;
    if (oe_strncpy_s(
            args->module,
            sizeof(char) * OE_LOG_MODULE_LEN_MAX,
            module, oe_strlen(module)) != OE_OK)
        goto done;

    oe_va_list ap;
    oe_va_start(ap, fmt);
    int n = oe_vsnprintf(args->message, OE_LOG_MESSAGE_LEN_MAX, fmt, ap);
    oe_va_end(ap);

    if (n < 0)
        goto done;

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
