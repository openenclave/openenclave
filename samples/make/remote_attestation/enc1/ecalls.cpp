// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include "../args.h"
#include "../common/dispatcher.h"

template <typename T>
bool is_outside_enclave(T* args)
{
    if (oe_is_outside_enclave(args, sizeof(T)))
        return true;
    return false;
}

#define DISPATCH(x)                          \
    if (!is_outside_enclave(arg))            \
    {                                        \
        arg->success = OE_INVALID_PARAMETER; \
        return;                              \
    }                                        \
    dispatcher.x(arg);

// For this purpose of this example: demonstrating how to do remote attestation
// g_EnclaveSecretData is hardcoded as part of the enclave. In this sample, the
// secret data is hard coded as part of the enclave binary. In a real world
// enclave implementation, secrets are never hard coded in the enclave binary
// since the enclave binary itself is not encrypted. Instead, secrets are
// acquired via provisioning from a service (such as a cloud server) after
// successful attestation.
// This g_EnclaveSecretData holds the secret data specific to the holding
// enclave, it's only visible inside this secured enclave. Arbitrary enclave
// specific seccret data exchanged by the enclaves. In this sample, the first
// enclave sends its g_EnclaveSecretData (encrypted) to the second enclave. The
// this enclave decrypts the received data and adds it to its own
// g_EnclaveSecretData, and sends it back to the other enclave.
uint8_t g_EnclaveSecretData[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

// The SHA-256 hash of the public key in the private.pem file used to sign the
// enclave. This value is populated in the signer_id sub-field of a parsed
// oe_report_t's identity field.
// Note: if the private key (private.pem) used to sign the enclave is changed,
// the following hash must be updated.
uint8_t g_encalve2MRSigner[] = {0x21, 0x80, 0x00, 0xc2, 0xa2, 0xc6, 0x83, 0x21,
                                0xe2, 0xf3, 0x97, 0x06, 0x31, 0xc6, 0xf8, 0x7e,
                                0x0b, 0x94, 0x29, 0xa5, 0xbb, 0x7a, 0x64, 0x05,
                                0x82, 0x9e, 0xb5, 0xf0, 0x50, 0xe6, 0x06, 0x32};

EnclaveConfigData configData = {g_EnclaveSecretData, g_encalve2MRSigner};

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static EcallDispatcher dispatcher("Enclave1", &configData);

// ECalls

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
OE_ECALL void GetRemoteReportWithPubKey(GetRemoteReportWithPubKeyArgs* arg)
{
    DISPATCH(GetRemoteReportWithPublicKey);
}

// Attest and store the public key of another enclave.
OE_ECALL void VerifyReportAndSetPubKey(VerifyReportWithPubKeyArgs* arg)
{
    DISPATCH(VerifyReportAndSetKey);
}

// Encrypt message for another enclave using the public key stored for it.
OE_ECALL void GenerateEncryptedMessage(GenerateEncryptedMessageArgs* arg)
{
    DISPATCH(GenerateEncryptedData);
}

// Process encrypted message
OE_ECALL void ProcessEncryptedMessage(ProcessEncryptedMessageArgs* arg)
{
    DISPATCH(ProcessEncryptedData);
}
