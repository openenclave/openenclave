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
        const oe_uuid_t* format_id,
        format_settings_t* format_settings);

    int get_evidence_with_public_key(
        const oe_uuid_t* format_id,
        format_settings_t* format_settings,
        pem_key_t* pem_key,
        evidence_t* evidence);

    int verify_evidence_and_set_public_key(
        const oe_uuid_t* format_id,
        pem_key_t* pem_key,
        evidence_t* evidence);

    int generate_encrypted_message(message_t* message);

    int process_encrypted_message(message_t* message);

  private:
    bool initialize(const char* name);
};
