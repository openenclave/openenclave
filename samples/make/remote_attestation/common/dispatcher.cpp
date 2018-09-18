// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(NULL), m_attestation(NULL)
{
    m_EnclaveConfig = enclave_config;
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        goto exit;
    }

    m_attestation =
        new Attestation(m_crypto, m_EnclaveConfig->enclave_mrsigner);
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
int ecall_dispatcher::get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    uint8_t pem_public_key[512];
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* key_buf = NULL;
    int ret = 1;

    ENC_DEBUG_PRINTF("get_remote_report_with_pubkey");
    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a remote report for the public key so that the enclave that
    // receives the
    // key can attest this enclave. It is safer to use enclave memory for all
    // operations within the enclave. A malicious host could tamper with host
    // memory while enclave is processing it.
    // report = new uint8_t[OE_MAX_REPORT_SIZE];
    report = (uint8_t*)oe_host_malloc(OE_MAX_REPORT_SIZE);
    if (report == NULL)
    {
        goto exit;
    }
    report_size = OE_MAX_REPORT_SIZE;

    if (m_attestation->generate_remote_report(
            pem_public_key, sizeof(pem_public_key), report, &report_size))
    {
        *remote_report = report;
        *remote_report_size = report_size;

        key_buf = (uint8_t*)oe_host_malloc(512);
        if (key_buf == NULL)
        {
            goto exit;
        }
        memcpy(key_buf, pem_public_key, sizeof(pem_public_key));

        *pem_key = key_buf;
        *key_size = sizeof(pem_public_key);

        ret = 0;
        ENC_DEBUG_PRINTF("get_remote_report_with_pubkey succeeded");
    }
    else
    {
        ENC_DEBUG_PRINTF("get_remote_report_with_pubkey failed.");
    }

exit:
    if (ret != 0)
    {
        if (report)
            free(report);
        if (key_buf)
            free(key_buf);
    }
    return ret;
}

int ecall_dispatcher::verify_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* remote_report,
    size_t remote_report_size)
{
    int ret = 1;

    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the remote report and accompanying key.
    if (m_attestation->attest_remote_report(
            remote_report, remote_report_size, pem_key, key_size))
    {
        memcpy(m_crypto->get_the_other_enclave_public_key(), pem_key, key_size);
    }
    else
    {
        ENC_DEBUG_PRINTF("verify_report_and_set_pubkey failed.");
        goto exit;
    }
    ret = 0;
    ENC_DEBUG_PRINTF("verify_report_and_set_pubkey succeeded.");

exit:
    return ret;
}

int ecall_dispatcher::generate_encrypted_message(uint8_t** data, size_t* size)
{
    uint8_t encrypted_data_buf[1024];
    size_t encrypted_data_size;
    int ret = 1;

    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF("ecall_dispatcher initialization failed.");
        goto exit;
    }

    encrypted_data_size = sizeof(encrypted_data_buf);
    if (m_crypto->Encrypt(
            m_crypto->get_the_other_enclave_public_key(),
            m_EnclaveConfig->enclaveSecretData,
            ENCLAVE_SECRET_DATA_SIZE,
            encrypted_data_buf,
            &encrypted_data_size))
    {
        uint8_t* host_buf = (uint8_t*)oe_host_malloc(encrypted_data_size);
        memcpy(host_buf, encrypted_data_buf, encrypted_data_size);
        ENC_DEBUG_PRINTF(
            "enclave: generate_encrypted_message: encrypted_data_size = %ld",
            encrypted_data_size);
        *data = host_buf;
        *size = encrypted_data_size;
    }
    else
    {
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::process_encrypted_msg(
    uint8_t* encrypted_data,
    size_t encrypted_data_size)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        ENC_DEBUG_PRINTF("ecall_dispatcher initialization failed.");
        goto exit;
    }

    data_size = sizeof(data);
    if (m_crypto->decrypt(
            encrypted_data, encrypted_data_size, data, &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_EnclaveConfig->enclaveSecretData
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        ENC_DEBUG_PRINTF("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            printf("%d ", data[i]);
            if (m_EnclaveConfig->enclaveSecretData[i] != data[i])
            {
                printf(
                    "Expecting [0x%x] but received unexpected value "
                    "[0x%x]\n ",
                    m_EnclaveConfig->enclaveSecretData[i],
                    data[i]);
                ret = 1;
                break;
            }
        }
        printf("\n");
    }
    else
    {
        ENC_DEBUG_PRINTF(
            "Encalve:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    ENC_DEBUG_PRINTF("Decrypted data matches with the enclave internal secret "
                     "data: descryption validation succeeded");
    ret = 0;
exit:
    return ret;
}
