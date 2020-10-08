// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_VERIFIER_H
#define _OE_ENCLAVE_VERIFIER_H

#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>

#ifndef sgx_ql_qe_report_info_t
typedef struct _sgx_ql_qe_report_info_t
{
    sgx_nonce_t nonce;
    sgx_target_info_t app_enclave_target_info;
    sgx_report_t qe_report;
} sgx_ql_qe_report_info_t;
#endif

oe_result_t oe_verify_qve_report_and_identity(
    const uint8_t* p_quote,
    uint32_t quote_size,
    const sgx_ql_qe_report_info_t* p_qve_report_info,
    time_t expiration_check_date,
    uint32_t collateral_expiration_status,
    uint32_t quote_verification_result,
    const uint8_t* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint16_t qve_isvsvn_threshold);

#endif /* OE_ENCLAVE_VERIFIER_H */
