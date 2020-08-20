// Copyright (c) Open Enclave SDK contributors.
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
    const char* other_enclave_public_key_pem;
    size_t other_enclave_public_key_pem_size;
} enclave_config_data_t;

class ecall_dispatcher
{
  private:
    bool m_initialized;
    Crypto* m_crypto;
    Attestation* m_attestation;
    string m_name;
    enclave_config_data_t* m_enclave_config;
    unsigned char m_other_enclave_signer_id[32];

  public:
    ecall_dispatcher(const char* name, enclave_config_data_t* enclave_config);
    ~ecall_dispatcher();
    int get_enclave_format_settings(
        uint8_t** format_settings,
        size_t* format_settings_size);

    int get_targeted_evidence_with_public_key(
        uint8_t* format_settings,
        size_t format_settings_size,
        uint8_t** pem_key,
        size_t* pem_key_size,
        uint8_t** evidence_buffer,
        size_t* evidence_buffer_size);

    int verify_evidence_and_set_public_key(
        uint8_t* pem_key,
        size_t pem_key_size,
        uint8_t* evidence,
        size_t evidence_size);

    int generate_encrypted_message(uint8_t** data, size_t* size);

    int process_encrypted_message(
        uint8_t* encrypted_data,
        size_t encrypted_data_size);

  private:
    bool initialize(const char* name);
};
