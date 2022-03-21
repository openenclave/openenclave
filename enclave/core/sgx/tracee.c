// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/td.h>

#include "../tracee.h"
#include "report.h"

static volatile int _is_enclave_debug_allowed = -1;

// Read an enclave's identity attribute to see to if it was signed as an debug
// enclave
bool is_enclave_debug_allowed()
{
    oe_sgx_td_t* td = NULL;

    if (_is_enclave_debug_allowed != -1)
        goto done;

    td = oe_sgx_get_td();

    if (td && td->simulate)
    {
        // Enclave in simulate mode is treated as debug_allowed
        _is_enclave_debug_allowed = 1;
    }
    else
    {
        // Get a report on the enclave itself for enclave identity information
        sgx_report_t sgx_report;
        oe_result_t result = sgx_create_report(NULL, 0, NULL, 0, &sgx_report);

        if (result != OE_OK)
        {
            _is_enclave_debug_allowed = 0;
            goto done;
        }

        _is_enclave_debug_allowed =
            (sgx_report.body.attributes.flags & SGX_FLAGS_DEBUG) ? 1 : 0;
    }

done:
    return _is_enclave_debug_allowed == 1 ? true : false;
}

// Check the cached variable only
bool is_enclave_debug_allowed_cached()
{
    return _is_enclave_debug_allowed == 1 ? true : false;
}
