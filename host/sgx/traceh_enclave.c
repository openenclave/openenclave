// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include <string.h>
#include "enclave.h"

oe_result_t oe_log_enclave_init(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    log_level_t level = _log_level;

    _initialize_log_config();

    // Populate arg fields.
    oe_log_filter_t* arg = calloc(1, sizeof(oe_log_filter_t));
    if (arg == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }
    arg->path = enclave->path;
    arg->path_len = strlen(enclave->path);
    arg->level = level;
    // Call enclave
    result = oe_ecall(enclave, OE_ECALL_LOG_INIT, (uint64_t)arg, NULL);
    if (result != OE_OK)
        goto done;

    result = OE_OK;
done:
    return result;
}
