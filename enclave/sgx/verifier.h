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

oe_result_t sgx_verify_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const uint8_t* p_quote,
    uint32_t quote_size,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size);

#endif /* OE_ENCLAVE_VERIFIER_H */
