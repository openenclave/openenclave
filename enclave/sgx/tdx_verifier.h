// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_SGX_TDX_VERIFIER_H
#define _OE_ENCLAVE_SGX_TDX_VERIFIER_H

#include <openenclave/enclave.h>

oe_result_t tdx_verify_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const uint8_t* p_quote,
    uint32_t quote_size,
    const uint8_t* p_endorsements,
    uint32_t endorsements_size,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out);

#endif /* OE_ENCLAVE_SGX_TDX_VERIFIER_H */
