/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <sgx_utils.h>
#include <string.h>

sgx_status_t sgx_create_report(
    const sgx_target_info_t *target_info, 
    const sgx_report_data_t *report_data, 
    sgx_report_t *report)
{
    memset(report, 0, sizeof(*report));
#ifdef _DEBUG
    report->body.attributes.flags |= SGX_FLAGS_DEBUG;
#endif
    return SGX_SUCCESS;
}

sgx_status_t sgx_verify_report(const sgx_report_t *report)
{
    // TODO: implement this for TrustZone.
    return SGX_SUCCESS;
}
