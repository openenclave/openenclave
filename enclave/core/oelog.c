// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/oelog.h>
#include "oelog.h"

static oe_log_filter_t *log_filter = NULL;

oe_result_t _handle_oelog_init(uint64_t arg) {
    oe_result_t result = OE_FAILURE;
    if (log_filter != NULL) {
        oe_free(log_filter);
        log_filter = NULL;
    }
    log_filter = oe_malloc(sizeof(oe_log_filter_t));
    if (log_filter == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    oe_log_filter_t *filter = (oe_log_filter_t *) arg;
    log_filter->modules = filter->modules;
    log_filter->level = filter->level;
    result = OE_OK;

done:
    return result;

}

oe_result_t oe_log(log_level_t level, uint64_t module, const char *fmt, ...)
{
    oe_result_t result = OE_FAILURE;
    oe_log_args_t* args = NULL;

    // Check that log filter has been initialized
    if (log_filter == NULL)
        goto done;
    // Check that this message should be logged
    if (level < log_filter->level || ((module & log_filter->modules) == 0))
    {
        result = OE_OK;
        goto done;
    }
    // Validate input
    if (!fmt)
        goto done;
    // Prepare the structure
    if (!(args = oe_host_malloc(sizeof(oe_log_args_t))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    args->level = level;
    args->module = module;

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
