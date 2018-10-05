// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include "../common/dispatcher.h"
#include "../common/remoteattestation_t.h"

// For this purpose of this example: demonstrating how to do remote attestation
// g_enclave_secret_data is hardcoded as part of the enclave. In this sample,
// the secret data is hard coded as part of the enclave binary. In a real world
// enclave implementation, secrets are never hard coded in the enclave binary
// since the enclave binary itself is not encrypted. Instead, secrets are
// acquired via provisioning from a service (such as a cloud server) after
// successful attestation.
// This g_enclave_secret_data holds the secret data specific to the holding
// enclave, it's only visible inside this secured enclave. Arbitrary enclave
// specific secret data exchanged by the enclaves. In this sample, the first
// enclave sends its g_enclave_secret_data (encrypted) to the second enclave.
// The second enclave decrypts the received data and adds it to its own
// g_enclave_secret_data, and sends it back to the other enclave.
uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

// The SHA-256 hash of the public key in the private.pem file used to sign the
// enclave. This value is populated in the signer_id sub-field of a parsed
// oe_report_t's identity field.
// Note: if the private key (private.pem) used to sign the enclave is changed,
// the following hash must be updated.
uint8_t g_enclave1_mrsigner[] = {
    0xCA, 0x9A, 0xD7, 0x33, 0x14, 0x48, 0x98, 0x0A, 0xA2, 0x88, 0x90,
    0xCE, 0x73, 0xE4, 0x33, 0x63, 0x83, 0x77, 0xF1, 0x79, 0xAB, 0x44,
    0x56, 0xB2, 0xFE, 0x23, 0x71, 0x93, 0x19, 0x3A, 0x8D, 0x0A};

enclave_config_data_t config_data = {g_enclave_secret_data,
                                     g_enclave1_mrsigner};

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("Enclave2", &config_data);
const char* enclave_name = "Enclave2";

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    return dispatcher.get_remote_report_with_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

// Attest and store the public key of another enclave.
int verify_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* remote_report,
    size_t remote_report_size)
{
    return dispatcher.verify_report_and_set_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

// Encrypt message for another enclave using the public key stored for it.
int generate_encrypted_message(uint8_t** data, size_t* size)
{
    return dispatcher.generate_encrypted_message(data, size);
}

// Process encrypted message
int process_encrypted_msg(uint8_t* data, size_t size)
{
    return dispatcher.process_encrypted_msg(data, size);
}
