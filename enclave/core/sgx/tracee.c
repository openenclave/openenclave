// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/td.h>

#include "../tracee.h"
#include "report.h"

// Read an enclave's identity attribute to see to if it was signed as an debug
// enclave
bool is_enclave_debug_allowed()
{
    bool ret = false;
    oe_sgx_td_t* td = oe_sgx_get_td();

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
