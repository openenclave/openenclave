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
uint8_t g_encalve1MRSigner[] = {0xCA, 0x9A, 0xD7, 0x33, 0x14, 0x48, 0x98, 0x0A,
                                0xA2, 0x88, 0x90, 0xCE, 0x73, 0xE4, 0x33, 0x63,
                                0x83, 0x77, 0xF1, 0x79, 0xAB, 0x44, 0x56, 0xB2,
                                0xFE, 0x23, 0x71, 0x93, 0x19, 0x3A, 0x8D, 0x0A};

EnclaveConfigData configData = {g_EnclaveSecretData, g_encalve1MRSigner};

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static EcallDispatcher dispatcher("Enclave2", &configData);
// OE calls

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
OE_ECALL void GetRemoteReportWithPubKey(GetRemoteReportWithPubKeyArgs* arg)
{
    DISPATCH(GetRemoteReportWithPublicKey);
}

/**
 * Attest and store the public key of another enclave.
 */
OE_ECALL void VerifyReportAndSetPubKey(VerifyReportWithPubKeyArgs* arg)
{
    DISPATCH(VerifyReportAndSetKey);
}

/**
 * Encrypt message for another enclave using the public key stored for it.
*/
OE_ECALL void GenerateEncryptedMessage(GenerateEncryptedMessageArgs* arg)
{
    DISPATCH(GenerateEncryptedData);
}

/**
 * Process encrypted message
*/
OE_ECALL void ProcessEncryptedMessage(ProcessEncryptedMessageArgs* arg)
{
    DISPATCH(ProcessEncryptedData);
}
