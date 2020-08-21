// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
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

/**
 * Return the public key of this enclave along with the enclave's remote
 * evidence. The enclave that receives the key will use the remote evidence to
 * attest this enclave.
 */
int ecall_dispatcher::get_remote_evidence_with_public_key(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size)
{
    uint8_t pem_public_key[512];
    uint8_t* evidence = nullptr;
    size_t evidence_size = 0;
    uint8_t* key_buffer = nullptr;
    int ret = 1;

    TRACE_ENCLAVE("get_remote_evidence_with_public_key");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a remote evidence for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_remote_attestation_evidence(
            pem_public_key,
            sizeof(pem_public_key),
            &evidence,
            &evidence_size) == false)
    {
        TRACE_ENCLAVE("get_remote_evidence_with_public_key failed");
        goto exit;
    }

    // Allocate memory on the host and copy the evidence over.
    *evidence_buffer = (uint8_t*)oe_host_malloc(evidence_size);
    if (*evidence_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying evidence_buffer failed, out of memory");
        goto exit;
    }
    memcpy(*evidence_buffer, evidence, evidence_size);
    *evidence_buffer_size = evidence_size;
    oe_free_evidence(evidence);

    key_buffer = (uint8_t*)oe_host_malloc(512);
    if (key_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying key_buffer failed, out of memory");
        goto exit;
    }
    memcpy(key_buffer, pem_public_key, sizeof(pem_public_key));

    *pem_key = key_buffer;
    *key_size = sizeof(pem_public_key);

    ret = 0;
    TRACE_ENCLAVE("get_remote_evidence_with_public_key succeeded");

exit:
    if (ret != 0)
    {
        if (evidence)
            oe_free_evidence(evidence);
        if (key_buffer)
            oe_host_free(key_buffer);
        if (*evidence_buffer)
            oe_host_free(*evidence_buffer);
    }
    return ret;
}

int ecall_dispatcher::verify_evidence_and_set_public_key(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* evidence,
    size_t evidence_size)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the remote evidence and accompanying key.
    if (m_attestation->attest_remote_attestation_evidence(
            evidence, evidence_size, pem_key, key_size) == false)
    {
        TRACE_ENCLAVE("verify_evidence_and_set_public_key failed.");
        goto exit;
    }

    memcpy(m_crypto->get_the_other_enclave_public_key(), pem_key, key_size);

    ret = 0;
    TRACE_ENCLAVE("verify_evidence_and_set_public_key succeeded.");

exit:
    return ret;
}
