// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../../common/tls_client_enc_pubkey.h"
#include "tls_client_t.h"

#define ENCLAVE_SECRET_DATA_SIZE 16

typedef struct _enclave_config_data
{
    uint8_t* enclave_secret_data;
    const char* other_enclave_pubkey_pem;
    size_t other_enclave_pubkey_pem_size;
} enclave_config_data_t;

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

enclave_config_data_t config_data = {g_enclave_secret_data,
                                     OTHER_ENCLAVE_PUBLIC_KEY,
                                     sizeof(OTHER_ENCLAVE_PUBLIC_KEY)};
int ecall_launch_tls_client(char* server_name, char* server_port)
{
    return launch_tls_client(server_name, server_port);
}
