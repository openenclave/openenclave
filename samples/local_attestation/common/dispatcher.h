// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "attestation.h"
#include "crypto.h"

using namespace std;

typedef struct _enclave_config_data
{
    uint8_t* enclave_secret_data;
    const char* other_enclave_pubkey_pem;
    size_t other_enclave_pubkey_pem_size;
} enclave_config_data_t;

class ecall_dispatcher
{
  private:
    bool m_initialized;
    Crypto* m_crypto;
    Attestation* m_attestation;
    string m_name;
    enclave_config_data_t* m_enclave_config;
    unsigned char m_other_enclave_mrsigner[32];

  public:
    ecall_dispatcher(const char* name, enclave_config_data_t* enclave_config);
    ~ecall_dispatcher();

    int get_target_info(uint8_t** target_info_buffer, size_t* target_info_size);
    int get_targeted_report_with_pubkey(
        uint8_t* target_info_buffer,
        size_t target_info_size,
        uint8_t** pem_key,
        size_t* pem_key_size,
        uint8_t** report,
        size_t* report_size);

    int verify_report_and_set_pubkey(
        uint8_t* pem_key,
        size_t pem_key_size,
        uint8_t* local_report,
        size_t report_size);
    int generate_encrypted_message(uint8_t** data, size_t* size);
    int process_encrypted_msg(
        uint8_t* encrypted_data,
        size_t encrypted_data_size);

  private:
    bool initialize(const char* name);
};
