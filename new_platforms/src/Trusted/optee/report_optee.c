/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/enclave.h>

#include "cyres_optee.h"
#include "enclavelibc.h"

oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    if (report_buffer == NULL || report_buffer_size == NULL)
        return OE_INVALID_PARAMETER;

    return get_cyres_cert_chain(report_buffer, report_buffer_size);
}

oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    /* Not supported */
    return OE_UNSUPPORTED;
}
