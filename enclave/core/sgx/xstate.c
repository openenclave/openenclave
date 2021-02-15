// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/td.h>
#include "report.h"

int oe_is_xsave_supported = 0;

oe_result_t oe_set_is_xsave_supported()
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sgx_td_t* td = oe_sgx_get_td();
    if (!td->simulate)
    {
        sgx_report_t report;
        OE_CHECK_NO_TRACE(sgx_create_report(NULL, 0, NULL, 0, &report));
        oe_is_xsave_supported =
            (report.body.attributes.xfrm != SGX_XFRM_LEGACY) ? 1 : 0;
    }
    result = OE_OK;
done:
    return result;
}
