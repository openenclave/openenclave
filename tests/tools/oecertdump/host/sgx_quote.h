// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SGX_QUOTE
#define _SGX_QUOTE

#include <openenclave/host.h>
#include "../../../../host/sgx/platformquoteprovider.h"

void log(const char* fmt, ...);
void output_certificate(const uint8_t* data, size_t data_len);
void decode_certificate_pem(FILE* file, const uint8_t* data, size_t data_len);
void decode_crl_pem(const uint8_t* data, size_t data_len);
void parse_certificate_extension(const uint8_t* data, size_t data_len);
void output_certificate_chain(
    const uint8_t* data,
    size_t data_len,
    bool is_report_buffer);
void oecertdump_quote_provider_log(
    sgx_ql_log_level_t level,
    const char* message);
void set_log_callback();

oe_result_t generate_sgx_report(oe_enclave_t* enclave, bool verbose);
oe_result_t output_sgx_report(const uint8_t* report, size_t report_size);
oe_result_t get_sgx_report_from_certificate(
    const uint8_t* certificate_in_der,
    size_t certificate_in_der_length,
    uint8_t** report,
    size_t* report_size);

#endif // _SGX_QUOTE