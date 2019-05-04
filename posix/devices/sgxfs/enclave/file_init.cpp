// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include "common.h"
#include "sgx_error.h"
#include <openenclave/enclave.h>
#define sgx_create_report __sgx_create_report__
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "linux-sgx/sdk/protected_fs/sgx_tprotected_fs/file_init.cpp"
#include <stdio.h>
// clang-format on

sgx_status_t __sgx_create_report__(
    const sgx_target_info_t* target_info,
    const sgx_report_data_t* report_data,
    sgx_report_t* report)
{
    uint8_t tmp[OE_MAX_REPORT_SIZE];
    size_t tmp_used = sizeof(sgx_report_t) + 16;

    (void)target_info;
    (void)report_data;

    if (oe_get_report_v1(0, NULL, 0, NULL, 0, tmp, &tmp_used) != OE_OK)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    // OE has a report header in front of the sgx report of size 16 bytes. We
    // can get a pointer to past
    // the header and then cast it to an actual sgx_report_t
    sgx_report_t* sgxreport = (sgx_report_t*)(tmp + 16);

    *report = *sgxreport;

    return SGX_SUCCESS;
}
