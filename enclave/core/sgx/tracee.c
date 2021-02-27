// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/td.h>

#include "../tracee.h"
#include "report.h"

// Enclave is assumed to be non debuggable unless proven otherwise.
static bool _is_enclave_debug_allowed = false;
static bool _initialized = false;

// Read an enclave's identity attribute to see to if it was signed as an debug
// enclave
void oe_initialize_is_enclave_debug_allowed(oe_sgx_td_t* td)
{
    if (!_initialized)
    {
        if (td->simulate)
        {
            // enclave in simulate mode is treated as debug_allowed
            _is_enclave_debug_allowed = true;
        }
        else
        {
            // get a report on the enclave itself for enclave identity
            // information
            sgx_report_t sgx_report;
            oe_result_t result =
                sgx_create_report(NULL, 0, NULL, 0, &sgx_report);
            if (result != OE_OK)
                return;

            _is_enclave_debug_allowed =
                (sgx_report.body.attributes.flags & SGX_FLAGS_DEBUG) != 0;
        }
        _initialized = true;
    }
}

bool oe_is_enclave_debug_allowed()
{
    return _is_enclave_debug_allowed;
}
