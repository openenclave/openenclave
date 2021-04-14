// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SGX_QUOTE
#define _SGX_QUOTE

#include <openenclave/host.h>
#include "../../../../host/sgx/platformquoteprovider.h"
#include "../oecert_enc_pubkey.h"

void log(const char* fmt, ...);
void oecert_quote_provider_log(sgx_ql_log_level_t level, const char* message);
void set_log_callback();

void dump_certificate(const uint8_t* data, size_t data_len);

oe_result_t output_file(
    const char* file_name,
    const uint8_t* data,
    size_t data_size);

oe_result_t verify_signer_id(
    const char* siging_public_key,
    size_t siging_public_key_size,
    uint8_t* signer_id,
    size_t signer_id_size);

oe_result_t dump_oe_report(const uint8_t* report, size_t report_size);

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
