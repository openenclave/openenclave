// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <common/attestation_t.h>
#include <common/dispatcher.h>
#include <enclave_b_pubkey.h>
#include <openenclave/enclave.h>

// For this purpose of this example: demonstrating how to do attestation
// g_enclave_secret_data is hardcoded as part of the enclave. In this sample,
// the secret data is hard coded as part of the enclave binary. In a real world
// enclave implementation, secrets are never hard coded in the enclave binary
// since the enclave binary itself is not encrypted. Instead, secrets are
// acquired via provisioning from a service (such as a cloud server) after
// successful attestation.
// The g_enclave_secret_data holds the secret data specific to the holding
// enclave, it's only visible inside this secured enclave. Arbitrary enclave
// specific secret data exchanged by the enclaves. In this sample, the first
// enclave sends its g_enclave_secret_data (encrypted) to the second enclave.
// The second enclave decrypts the received data and adds it to its own
// g_enclave_secret_data, and sends it back to the other enclave.
uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

enclave_config_data_t config_data = {
    g_enclave_secret_data,
    OTHER_ENCLAVE_PUBLIC_KEY,
    sizeof(OTHER_ENCLAVE_PUBLIC_KEY)};

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("Enclave1", &config_data);
const char* enclave_name = "Enclave1";
int get_enclave_format_settings(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings)
{
    return dispatcher.get_enclave_format_settings(format_id, format_settings);
}

/**
 * Return the public key of this enclave along with the enclave's
 * evidence. Another enclave can use the evidence to attest the enclave
 * and verify the integrity of the public key.
 */
int get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    return dispatcher.get_evidence_with_public_key(
        format_id, format_settings, pem_key, evidence);
}

// Attest and store the public key of another enclave.
int verify_evidence_and_set_public_key(
    const oe_uuid_t* format_id,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    return dispatcher.verify_evidence_and_set_public_key(
        format_id, pem_key, evidence);
}

// Encrypt message for another enclave using the public key stored for it.
int generate_encrypted_message(message_t* message)
{
    return dispatcher.generate_encrypted_message(message);
}

// Process encrypted message
int process_encrypted_message(message_t* message)
{
    return dispatcher.process_encrypted_message(message);
}
