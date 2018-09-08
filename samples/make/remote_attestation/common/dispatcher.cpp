// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>
#include "../args.h"

EcallDispatcher::EcallDispatcher(
    const char* name,
    EnclaveConfigData* enclaveConfig)
    : m_pCrypto(NULL), m_attestation(NULL)
{
    m_EnclaveConfig = enclaveConfig;
    m_Initialized = initialize(name);
}

EcallDispatcher::~EcallDispatcher()
{
    if (m_pCrypto)
        delete m_pCrypto;

    if (m_attestation)
        delete m_attestation;
}

bool EcallDispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_pCrypto = new Crypto();
    if (m_pCrypto == NULL)
    {
        goto exit;
    }

    m_attestation =
        new Attestation(m_pCrypto, m_EnclaveConfig->enclaveMRSigner);
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
    uint8_t pemPublicKey[512];
    uint8_t* remoteReport = NULL;
    size_t remoteReportSize = 0;

    if (m_Initialized == false)
    {
        ENC_DEBUG_PRINTF("EcallDispatcher initialization failed.");
        goto exit;
    }

    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        goto exit;

    m_pCrypto->RetrievePublicKey(pemPublicKey);

    // Generate a remote report for the public key so that the enclave that
    // receives the
    // key can attest this enclave. It is safer to use enclave memory for all
    // operations within the enclave. A malicious host could tamper with host
    // memory while enclave is processing it.
    remoteReport = new uint8_t[OE_MAX_REPORT_SIZE];
    remoteReportSize = OE_MAX_REPORT_SIZE;

    if (m_attestation->GenerateRemoteReport(
            pemPublicKey,
            sizeof(pemPublicKey),
            remoteReport,
            &remoteReportSize))
    {
        // Copy the remote report to the host memory.
        uint8_t* hostRemoteReport = (uint8_t*)oe_host_malloc(remoteReportSize);
        memcpy(hostRemoteReport, remoteReport, remoteReportSize);

        // Create return parameter.
        RemoteReportWithPubKey* reportWithPubKey =
            (RemoteReportWithPubKey*)oe_host_malloc(
                sizeof(RemoteReportWithPubKey));
        memcpy(reportWithPubKey->pemKey, pemPublicKey, sizeof(pemPublicKey));
        reportWithPubKey->remoteReport = hostRemoteReport;
        reportWithPubKey->remoteReportSize = remoteReportSize;

        arg->reportWithPubKey = reportWithPubKey;
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
    if (remoteReport)
        delete[] remoteReport;
}
void EcallDispatcher::VerifyReportAndSetKey(VerifyReportWithPubKeyArgs* arg)
{
    VerifyReportWithPubKeyArgs encArg = *arg;
    RemoteReportWithPubKey reportWithPubKey;
    uint8_t* remoteReport = NULL;

    if (m_Initialized == false)
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

    reportWithPubKey = *encArg.reportWithPubKey;
    if (!reportWithPubKey.remoteReport ||
        !oe_is_outside_enclave(
            reportWithPubKey.remoteReport, reportWithPubKey.remoteReportSize))
        goto exit;

    remoteReport = new uint8_t[reportWithPubKey.remoteReportSize];
    memcpy(
        remoteReport,
        reportWithPubKey.remoteReport,
        reportWithPubKey.remoteReportSize);

    // Attest the remote report and accompanying key.
    if (m_attestation->AttestRemoteReport(
            remoteReport,
            reportWithPubKey.remoteReportSize,
            reportWithPubKey.pemKey,
            sizeof(reportWithPubKey.pemKey)))
    {
        memcpy(
            m_pCrypto->get_2ndenclave_public_key(),
            reportWithPubKey.pemKey,
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
    if (remoteReport)
        delete[] remoteReport;
}
void EcallDispatcher::GenerateEncryptedData(GenerateEncryptedMessageArgs* arg)
{
    uint8_t encryptedDataBuffer[1024];
    size_t encryptedDataSize;

    if (m_Initialized == false)
    {
        ENC_DEBUG_PRINTF(
            "%s: EcallDispatcher initialization failed.\n", m_name.c_str());
        goto exit;
    }

    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        goto exit;

    encryptedDataSize = sizeof(encryptedDataBuffer);
    if (m_pCrypto->Encrypt(
            m_pCrypto->get_2ndenclave_public_key(),
            m_EnclaveConfig->enclaveSecretData,
            sizeof(ENCLAVE_SECRET_DATA_SIZE),
            encryptedDataBuffer,
            &encryptedDataSize))
    {
        uint8_t* hostBuffer = (uint8_t*)oe_host_malloc(encryptedDataSize);
        memcpy(hostBuffer, encryptedDataBuffer, encryptedDataSize);
        arg->data = hostBuffer;
        arg->size = encryptedDataSize;
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
    ProcessEncryptedMessageArgs encArg = *arg;
    uint8_t* encryptedData = NULL;
    uint8_t data[ENCLAVE_SECRET_DATA_SIZE];
    size_t dataSize = 0;

    if (m_Initialized == false)
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

    if (!encArg.data || !oe_is_outside_enclave(encArg.data, encArg.size))
        goto exit;

    encryptedData = new uint8_t[encArg.size];
    memcpy(encryptedData, encArg.data, encArg.size);

    dataSize = sizeof(data);

    arg->success = true;

    if (m_pCrypto->Decrypt(encryptedData, encArg.size, data, &dataSize))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_EnclaveConfig->enclaveSecretData
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        printf("Decrypted data: ");
        for (uint32_t i = 0; i < dataSize; ++i)
        {
            printf("%d ", data[i]);
            if (m_EnclaveConfig->enclaveSecretData[i] != data[i])
            {
                printf(
                    "%s: Expecting [0x%x] but received unexpected value "
                    "[0x%x]\n ",
                    m_name.c_str(),
                    m_EnclaveConfig->enclaveSecretData[i],
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
    if (encryptedData)
        delete[] encryptedData;
}
