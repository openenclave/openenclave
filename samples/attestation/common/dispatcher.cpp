// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(nullptr), m_attestation(nullptr)
{
    m_enclave_config = enclave_config;
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
    if (m_crypto == nullptr)
    {
        goto exit;
    }

    {
        size_t other_enclave_signer_id_size = sizeof(m_other_enclave_signer_id);
        // TODO: the following call is not TEE-agnostic.
        if (oe_sgx_get_signer_id_from_public_key(
                m_enclave_config->other_enclave_public_key_pem,
                m_enclave_config->other_enclave_public_key_pem_size,
                m_other_enclave_signer_id,
                &other_enclave_signer_id_size) != OE_OK)
        {
            goto exit;
        }
    }

    m_attestation = new Attestation(m_crypto, m_other_enclave_signer_id);
    if (m_attestation == nullptr)
    {
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

int ecall_dispatcher::get_enclave_format_settings(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings)
{
    uint8_t* format_settings_buffer = nullptr;
    size_t format_settings_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    // Generate a format settings so that the enclave that receives this format
    // settings can attest this enclave.
    TRACE_ENCLAVE("get_enclave_format_settings");
    if (m_attestation->get_format_settings(
            format_id, &format_settings_buffer, &format_settings_size) == false)
    {
        TRACE_ENCLAVE("get_enclave_format_settings failed");
        goto exit;
    }

    if (format_settings_buffer && format_settings_size)
    {
        format_settings->buffer = (uint8_t*)malloc(format_settings_size);
        if (format_settings->buffer == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("copying format_settings failed, out of memory");
            goto exit;
        }
        memcpy(
            format_settings->buffer,
            format_settings_buffer,
            format_settings_size);
        format_settings->size = format_settings_size;
        oe_verifier_free_format_settings(format_settings_buffer);
    }
    else
    {
        format_settings->buffer = nullptr;
        format_settings->size = 0;
    }
    ret = 0;

exit:

    if (ret != 0)
        TRACE_ENCLAVE("get_enclave_format_settings failed.");
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's
 * evidence. The enclave that receives the key will use the evidence to
 * attest this enclave.
 */
int ecall_dispatcher::get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    format_settings_t* format_settings,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    uint8_t pem_public_key[512];
    uint8_t* evidence_buffer = nullptr;
    size_t evidence_size = 0;
    int ret = 1;

    TRACE_ENCLAVE("get_evidence_with_public_key");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate evidence for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_attestation_evidence(
            format_id,
            format_settings->buffer,
            format_settings->size,
            pem_public_key,
            sizeof(pem_public_key),
            &evidence_buffer,
            &evidence_size) == false)
    {
        TRACE_ENCLAVE("get_evidence_with_public_key failed");
        goto exit;
    }

    evidence->buffer = (uint8_t*)malloc(evidence_size);
    if (evidence->buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying evidence_buffer failed, out of memory");
        goto exit;
    }
    memcpy(evidence->buffer, evidence_buffer, evidence_size);
    evidence->size = evidence_size;
    oe_free_evidence(evidence_buffer);

    pem_key->buffer = (uint8_t*)malloc(sizeof(pem_public_key));
    if (pem_key->buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying key_buffer failed, out of memory");
        goto exit;
    }
    memcpy(pem_key->buffer, pem_public_key, sizeof(pem_public_key));
    pem_key->size = sizeof(pem_public_key);

    ret = 0;
    TRACE_ENCLAVE("get_evidence_with_public_key succeeded");

exit:
    if (ret != 0)
    {
        if (evidence_buffer)
            oe_free_evidence(evidence_buffer);
        if (pem_key)
        {
            free(pem_key->buffer);
            pem_key->size = 0;
        }
        if (evidence)
        {
            free(evidence->buffer);
            evidence->size = 0;
        }
    }
    return ret;
}

int ecall_dispatcher::verify_evidence_and_set_public_key(
    const oe_uuid_t* format_id,
    pem_key_t* pem_key,
    evidence_t* evidence)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the evidence and accompanying key.
    if (m_attestation->attest_attestation_evidence(
            format_id,
            evidence->buffer,
            evidence->size,
            pem_key->buffer,
            pem_key->size) == false)
    {
        TRACE_ENCLAVE("verify_evidence_and_set_public_key failed.");
        goto exit;
    }

    memcpy(
        m_crypto->get_the_other_enclave_public_key(),
        pem_key->buffer,
        pem_key->size);

    ret = 0;
    TRACE_ENCLAVE("verify_evidence_and_set_public_key succeeded.");

exit:
    return ret;
}

int ecall_dispatcher::generate_encrypted_message(message_t* message)
{
    uint8_t encrypted_data_buffer[1024];
    size_t encrypted_data_size;
    uint8_t* buffer;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    encrypted_data_size = sizeof(encrypted_data_buffer);
    if (m_crypto->Encrypt(
            m_crypto->get_the_other_enclave_public_key(),
            m_enclave_config->enclave_secret_data,
            ENCLAVE_SECRET_DATA_SIZE,
            encrypted_data_buffer,
            &encrypted_data_size) == false)
    {
        TRACE_ENCLAVE("enclave: generate_encrypted_message failed");
        goto exit;
    }

    buffer = (uint8_t*)malloc(encrypted_data_size);
    if (buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying host_buffer failed, out of memory");
        goto exit;
    }
    memcpy(buffer, encrypted_data_buffer, encrypted_data_size);
    TRACE_ENCLAVE(
        "enclave: generate_encrypted_message: encrypted_data_size = %ld",
        encrypted_data_size);

    message->data = buffer;
    message->size = encrypted_data_size;

    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::process_encrypted_message(message_t* message)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    data_size = sizeof(data);
    if (m_crypto->decrypt(message->data, message->size, data, &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_enclave_config->enclave_secret_data.
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        TRACE_ENCLAVE("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            printf("%d ", data[i]);
            if (m_enclave_config->enclave_secret_data[i] != data[i])
            {
                printf(
                    "Expecting [0x%x] but received unexpected value "
                    "[0x%x]\n ",
                    m_enclave_config->enclave_secret_data[i],
                    data[i]);
                ret = 1;
                break;
            }
        }
        printf("\n");
    }
    else
    {
        TRACE_ENCLAVE("Encalve:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    TRACE_ENCLAVE("Decrypted data matches with the enclave internal secret "
                  "data: descryption validation succeeded");
    ret = 0;
exit:
    return ret;
}
