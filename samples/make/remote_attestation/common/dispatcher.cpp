// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>
#include "../args.h"

EcallDispatcher::EcallDispatcher(
    const char* name,
    EnclaveConfigData* enclave_config)
    : m_p_crypto(NULL), m_attestation(NULL)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
}

EcallDispatcher::~EcallDispatcher()
{
    if (m_p_crypto)
        delete m_p_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool EcallDispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_p_crypto = new Crypto();
    if (m_p_crypto == NULL)
    {
        goto exit;
    }

    m_attestation =
        new Attestation(m_p_crypto, m_enclave_config->enclave_mr_signer);
    if (m_attestation == NULL)
    {
        goto exit;
    }
    ret = true;
exit:
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * The enclave that receives the key will use the remote report to attest this
 * enclave.
 */
void EcallDispatcher::GetRemoteReportWithPublicKey(
    GetRemoteReportWithPubKeyArgs* arg)
{
    uint8_t pem_public_key[512];
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;

    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF("EcallDispatcher initialization failed.");
        goto exit;
    }

    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        goto exit;

    m_p_crypto->RetrievePublicKey(pem_public_key);

    // Generate a remote report for the public key so that the enclave that
    // receives the
    // key can attest this enclave. It is safer to use enclave memory for all
    // operations within the enclave. A malicious host could tamper with host
    // memory while enclave is processing it.
    remote_report = new uint8_t[OE_MAX_REPORT_SIZE];
    remote_report_size = OE_MAX_REPORT_SIZE;

    if (m_attestation->GenerateRemoteReport(
            pem_public_key,
            sizeof(pem_public_key),
            remote_report,
            &remote_report_size))
    {
        // Copy the remote report to the host memory.
        uint8_t* host_remote_report =
            (uint8_t*)oe_host_malloc(remote_report_size);
        memcpy(host_remote_report, remote_report, remote_report_size);

        // Create return parameter.
        RemoteReportWithPubKey* report_with_pub_key =
            (RemoteReportWithPubKey*)oe_host_malloc(
                sizeof(RemoteReportWithPubKey));
        memcpy(
            report_with_pub_key->pem_key,
            pem_public_key,
            sizeof(pem_public_key));
        report_with_pub_key->remote_report = host_remote_report;
        report_with_pub_key->remote_report_size = remote_report_size;

        arg->report_with_pub_key = report_with_pub_key;
        arg->success = true;

        ENC_DEBUG_PRINTF(
            "%s: GetRemoteReportWithPubKey succeeded\n", m_name.c_str());
    }
    else
    {
        ENC_DEBUG_PRINTF(
            "%s: GetRemoteReportWithPubKey failed.\n", m_name.c_str());
        arg->success = false;
    }

exit:
    if (remote_report)
        delete[] remote_report;
}
void EcallDispatcher::VerifyReportAndSetKey(VerifyReportWithPubKeyArgs* arg)
{
    VerifyReportWithPubKeyArgs enc_arg = *arg;
    RemoteReportWithPubKey report_with_pub_key;
    uint8_t* remote_report = NULL;

    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF(
            "%s: EcallDispatcher initialization failed.\n", m_name.c_str());
        goto exit;
    }

    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        goto exit;

    arg->success = false;

    // It is safer to use enclave memory for all operations within the enclave.
    // A malicious host could tamper with host memory while enclave is
    // processing it. Perform deep copy of argument.

    report_with_pub_key = *enc_arg.report_with_pub_key;
    if (!report_with_pub_key.remote_report ||
        !oe_is_outside_enclave(
            report_with_pub_key.remote_report,
            report_with_pub_key.remote_report_size))
        goto exit;

    remote_report = new uint8_t[report_with_pub_key.remote_report_size];
    memcpy(
        remote_report,
        report_with_pub_key.remote_report,
        report_with_pub_key.remote_report_size);

    // Attest the remote report and accompanying key.
    if (m_attestation->AttestRemoteReport(
            remote_report,
            report_with_pub_key.remote_report_size,
            report_with_pub_key.pem_key,
            sizeof(report_with_pub_key.pem_key)))
    {
        memcpy(
            m_p_crypto->get_2ndenclave_public_key(),
            report_with_pub_key.pem_key,
            PUBLIC_KEY_SIZE);

        arg->success = true;
        ENC_DEBUG_PRINTF(
            "%s: VerifyReportAndSetPubKey succeeded.\n", m_name.c_str());
    }
    else
    {
        ENC_DEBUG_PRINTF(
            "%s: VerifyReportAndSetPubKey failed.\n", m_name.c_str());
        arg->success = false;
    }

exit:
    if (remote_report)
        delete[] remote_report;
}
void EcallDispatcher::GenerateEncryptedData(GenerateEncryptedMessageArgs* arg)
{
    uint8_t encrypted_data_buffer[1024];
    size_t encrypted_data_size;

    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF(
            "%s: EcallDispatcher initialization failed.\n", m_name.c_str());
        goto exit;
    }

    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        goto exit;

    encrypted_data_size = sizeof(encrypted_data_buffer);
    if (m_p_crypto->Encrypt(
            m_p_crypto->get_2ndenclave_public_key(),
            m_enclave_config->enclave_secret_data,
            sizeof(ENCLAVE_SECRET_DATA_SIZE),
            encrypted_data_buffer,
            &encrypted_data_size))
    {
        uint8_t* host_buffer = (uint8_t*)oe_host_malloc(encrypted_data_size);
        memcpy(host_buffer, encrypted_data_buffer, encrypted_data_size);
        arg->data = host_buffer;
        arg->size = encrypted_data_size;
        arg->success = true;
    }
    else
    {
        arg->success = false;
    }
exit:
    return;
}

void EcallDispatcher::ProcessEncryptedData(ProcessEncryptedMessageArgs* arg)
{
    ProcessEncryptedMessageArgs enc_arg = *arg;
    uint8_t* encrypted_data = NULL;
    uint8_t data[ENCLAVE_SECRET_DATA_SIZE];
    size_t data_size = 0;

    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF(
            "%s: EcallDispatcher initialization failed.\n", m_name.c_str());
        goto exit;
    }

    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        goto exit;

    arg->success = false;

    // It is safer to use enclave memory for all operations within the enclave.
    // A malicious host could tamper with host memory while enclave is
    // processing it. Perform deep copy of argument.

    if (!enc_arg.data || !oe_is_outside_enclave(enc_arg.data, enc_arg.size))
        goto exit;

    encrypted_data = new uint8_t[enc_arg.size];
    memcpy(encrypted_data, enc_arg.data, enc_arg.size);

    data_size = sizeof(data);

    arg->success = true;

    if (m_p_crypto->Decrypt(encrypted_data, enc_arg.size, data, &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_enclave_config->enclave_secret_data
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        printf("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            printf("%d ", data[i]);
            if (m_enclave_config->enclave_secret_data[i] != data[i])
            {
                printf(
                    "%s: Expecting [0x%x] but received unexpected value "
                    "[0x%x]\n ",
                    m_name.c_str(),
                    m_enclave_config->enclave_secret_data[i],
                    data[i]);
                arg->success = false;
                break;
            }
        }
        printf("\n");
    }
    else
    {
        arg->success = false;
    }
exit:
    if (encrypted_data)
        delete[] encrypted_data;
}
