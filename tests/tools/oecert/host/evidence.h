// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SGX_QUOTE
#define _SGX_QUOTE

#include <openenclave/host.h>
#include "../../../../host/sgx/platformquoteprovider.h"

void log(const char* fmt, ...);
void oecert_quote_provider_log(sgx_ql_log_level_t level, const char* message);
void set_log_callback();

void dump_certificate(const uint8_t* data, size_t data_len);
void decode_certificate_pem(FILE* file, const uint8_t* data, size_t data_len);
void decode_crl_pem(const uint8_t* data, size_t data_len);
void parse_certificate_extension(const uint8_t* data, size_t data_len);
void dump_certificate_chain(
    const uint8_t* data,
    size_t data_len,
    bool is_report_buffer);
void dump_claims(const oe_claim_t* claims, size_t claims_size);

oe_result_t output_file(
    const char* file_name,
    const uint8_t* data,
    size_t data_size);
oe_result_t dump_sgx_quote(
    const uint8_t* quote_buffer,
    const uint8_t* boundary,
    size_t boundary_size);
oe_result_t dump_oe_report(const uint8_t* report, size_t report_size);
oe_result_t dump_oe_evidence(const uint8_t* evidence, size_t evidence_size);
oe_result_t dump_oe_endorsements(
    const uint8_t* endorsements,
    size_t endorsements_size);

oe_result_t get_oe_report_from_certificate(
    const uint8_t* certificate_in_der,
    size_t certificate_in_der_length,
    uint8_t** report,
    size_t* report_size);

oe_result_t generate_oe_report(
    oe_enclave_t* enclave,
    const char* report_filename,
    const char* endorsements_filename,
    bool verify,
    bool verbose);

oe_result_t generate_oe_evidence(
    oe_enclave_t* enclave,
    const char* evidence_filename,
    const char* endorsements_filename,
    bool verify,
    bool verbose);

#endif // _SGX_QUOTE
