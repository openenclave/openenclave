// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(NULL), m_attestation(NULL)
{
    m_enclave_config = enclave_config;
    m_channel_state = UNINITIALIZED_CHANNEL_STATE;
    initialize(name);
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
    uint8_t* modulus = NULL;
    size_t modulus_size;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        goto exit;
    }

    // Extract modulus from raw PEM.
    if (!m_crypto->get_rsa_modulus_from_pem(
            m_enclave_config->other_enclave_pubkey_pem,
            m_enclave_config->other_enclave_pubkey_pem_size,
            &modulus,
            &modulus_size))
    {
        goto exit;
    }

    // Reverse the modulus and compute sha256 on it.
    for (size_t i = 0; i < modulus_size / 2; i++)
    {
        uint8_t tmp = modulus[i];
        modulus[i] = modulus[modulus_size - 1 - i];
        modulus[modulus_size - 1 - i] = tmp;
    }

    // Calculate the MRSIGNER value which is the SHA256 hash of the
    // little endian representation of the public key modulus. This value
    // is populated by the signer_id sub-field of a parsed oe_report_t's
    // identity field.
    if (m_crypto->sha256(modulus, modulus_size, m_other_enclave_mrsigner) != 0)
    {
        goto exit;
    }

    m_attestation = new Attestation(m_crypto, m_other_enclave_mrsigner);
    if (m_attestation == NULL)
    {
        goto exit;
    }
    ret = true;
    m_channel_state = INITIAL_CHANNEL_STATE;

exit:
    if (modulus != NULL)
        free(modulus);

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

    TRACE_ENCLAVE("get_remote_report_with_pubkey");
    if (m_channel_state == UNINITIALIZED_CHANNEL_STATE)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a remote report for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_remote_report(
            pem_public_key, sizeof(pem_public_key), &report, &report_size))
    {
        // Allocate memory on the host and copy the report over.
        *remote_report = (uint8_t*)oe_host_malloc(report_size);
        if (*remote_report == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*remote_report, report, report_size);
        *remote_report_size = report_size;
        oe_free_report(report);

        key_buf = (uint8_t*)oe_host_malloc(512);
        if (key_buf == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_buf, pem_public_key, sizeof(pem_public_key));

        *pem_key = key_buf;
        *key_size = sizeof(pem_public_key);

        ret = 0;
        m_channel_state |= REMOTE_REPORT_OBTAINED;
        TRACE_ENCLAVE("get_remote_report_with_pubkey succeeded");
    }
    else
    {
        TRACE_ENCLAVE("get_remote_report_with_pubkey failed.");
    }

exit:
    if (ret != 0)
    {
        if (report)
            oe_free_report(report);
        if (key_buf)
            oe_host_free(key_buf);
        if (*remote_report)
            oe_host_free(*remote_report);
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

    if (m_channel_state == UNINITIALIZED_CHANNEL_STATE)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
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
        TRACE_ENCLAVE("verify_report_and_set_pubkey failed.");
        goto exit;
    }
    ret = 0;
    m_channel_state |= REMOTE_REPORT_VERIFIED;
    TRACE_ENCLAVE("verify_report_and_set_pubkey succeeded.");

exit:
    return ret;
}

int ecall_dispatcher::establish_secure_channel(uint8_t** key, size_t* key_size)
{
    uint8_t encrypted_key_buf[(DIGEST_SIZE * 8) + ENCRYPTED_KEY_SIZE];
    uint8_t signature[SIGNATURE_SIZE];
    uint8_t digest[DIGEST_SIZE]; // in bytes
    size_t encrypted_key_size = ENCRYPTED_KEY_SIZE;
    size_t signature_size = sizeof(signature);
    size_t total_size = sizeof(encrypted_key_buf);

    int ret = 1;

    if ((m_channel_state & MUTUAL_ATTESTATION_STATE) !=
        MUTUAL_ATTESTATION_STATE)
    {
        TRACE_ENCLAVE("ecall_dispatcher establish_secure_channel failed as "
                      "mutual attestation incomplete.");
        goto exit;
    }

    // Step 1 - Create an ephemeral symmetric key;
    // Initialize sequence number to 0, numbering will start at 1
    if (oe_random(m_enclave_config->sym_key, DIGEST_SIZE) != OE_OK)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed to generate "
                      "ephemeral symmetric key.");
        goto exit;
    }

    TRACE_ENCLAVE("enclave: establish_secure_channel: Generated random "
                  "symmetric key successfully");

    m_enclave_config->sequence_number = 0;

    // Step 2- Encrypt the symmetric key with the other enclave's public key
    if (m_crypto->encrypt(
            m_crypto->get_the_other_enclave_public_key(),
            m_enclave_config->sym_key,
            DIGEST_SIZE,
            encrypted_key_buf,
            &encrypted_key_size))

    {
        // We allocate memory in the host is so that the encrypted data
        // can be accessed by the hosts. Filed issue #1956 to deprecate
        // oe_host_malloc
        uint8_t* host_buf = (uint8_t*)oe_host_malloc(total_size);
        if (host_buf == NULL)
        {
            TRACE_ENCLAVE(
                "enclave: establish_secure_channel: oe_host_malloc failed.");
            goto exit;
        }

        // Step 3 - Compute a SHA hash of the encrypted key
        if (m_crypto->sha256(encrypted_key_buf, encrypted_key_size, digest) !=
            0)
        {
            goto exit;
        }

        TRACE_ENCLAVE("enclave: establish_secure_channel: Computed SHA hash "
                      "of the encrypted key");

        // Step 4 - Sign this SHA hash with my enclave's private key
        if (m_crypto->sign(
                digest, sizeof(digest), signature, &signature_size) != 0)
        {
            goto exit;
        }

        TRACE_ENCLAVE(
            "enclave: establish_secure_channel: signature_size = %ld",
            signature_size);

        if ((encrypted_key_size != ENCRYPTED_KEY_SIZE) ||
            (signature_size != SIGNATURE_SIZE))
        {
            TRACE_ENCLAVE("enclave: establish_secure_channel: failed as "
                          "encrypted data size or signature size is not 256");
        }
        // Step 5 - Send digest plus signature to the other enclave
        memcpy(host_buf, encrypted_key_buf, total_size);

        TRACE_ENCLAVE(
            "enclave: establish_secure_channel: total_size = %ld", total_size);
        *key = host_buf;
        *key_size = total_size;
    }
    else
    {
        goto exit;
    }
    ret = 0;
    m_channel_state = SECURE_CHANNEL_STATE;
exit:
    return ret;
}

/* Encrypted key_buf should contain encrypted key followed by signature
 */
int ecall_dispatcher::acknowledge_secure_channel(
    uint8_t* encrypted_key_buf,
    size_t encrypted_key_size)
{
    int ret = 1;
    uint8_t* data;
    size_t data_size = DIGEST_SIZE;
    uint8_t digest[DIGEST_SIZE];
    int rc;

    /* Steps --
     *   1) Verify Signature; if good proceed to step 2
     *   2) Decrypt the key using your own private key
     *   3) Now use this key with sequence number to communicate further
     */
    unsigned char* signature = &encrypted_key_buf[ENCRYPTED_KEY_SIZE];
    size_t signature_size = SIGNATURE_SIZE;

    data = m_enclave_config->sym_key;
    m_enclave_config->sequence_number = 0;

    if ((m_channel_state & MUTUAL_ATTESTATION_STATE) !=
        MUTUAL_ATTESTATION_STATE)
    {
        TRACE_ENCLAVE("ecall_dispatcher acknowledge_secure_channel failed as "
                      "mutual attestation is incomplete");
        goto exit;
    }

    if (m_crypto->sha256(encrypted_key_buf, ENCRYPTED_KEY_SIZE, digest) != 0)
    {
        goto exit;
    }

    rc = m_crypto->verify_sign(
        m_crypto->get_the_other_enclave_public_key(),
        digest,
        DIGEST_SIZE,
        signature,
        signature_size);
    if (rc != 0)
    {
        TRACE_ENCLAVE(
            "enclave: acknowledge_secure_channel: signature "
            "verification failed with %x\n",
            rc);
        goto exit;
    }

    TRACE_ENCLAVE("enclave: acknowledge_secure_channel: signature verified ok");

    if (m_crypto->decrypt(
            encrypted_key_buf, ENCRYPTED_KEY_SIZE, data, &data_size))
    {
        TRACE_ENCLAVE(
            "enclave: acknowledge_secure_channel: extracted symmetric key size "
            "= %ld",
            data_size);
    }
    else
    {
        TRACE_ENCLAVE("enclave: acknowledge_secure_channel: symmetric key "
                      "decrypt failed");
        goto exit;
    }

    ret = 0;
    m_channel_state = SECURE_CHANNEL_STATE;
exit:
    return ret;
}

int ecall_dispatcher::generate_encrypted_message(uint8_t** data, size_t* size)
{
    uint8_t encrypted_data_buf[ENCLAVE_SECRET_DATA_SIZE];
    uint8_t tag_str[ENCLAVE_SECRET_DATA_SIZE];
    size_t encrypted_data_size;
    size_t total_size;
    uint8_t iv_str[IV_SIZE];
    int ret = 1;

    if (m_channel_state != SECURE_CHANNEL_STATE)
    {
        TRACE_ENCLAVE(
            "ecall_dispatcher failed as Secure Channel isn't available.");
        goto exit;
    }

    encrypted_data_size = sizeof(encrypted_data_buf);
    memset(encrypted_data_buf, 0x00, encrypted_data_size);
    if (m_crypto->encrypt_gcm(
            m_enclave_config->sym_key,
            ++(m_enclave_config->sequence_number),
            m_enclave_config->enclave_secret_data,
            ENCLAVE_SECRET_DATA_SIZE,
            iv_str,
            encrypted_data_buf,
            &encrypted_data_size,
            tag_str))
    {
        // Reason we allocate memory in the host is so that the encrypted data
        // can be accessed by the hosts - aka real world scenario where we have
        // 2 hosts and two enclaves. Allocate space for iv_str & tag_str to be
        // appended after encrypted data
        total_size = ENCLAVE_SECRET_DATA_SIZE * 2 + IV_SIZE;
        uint8_t* host_buf = (uint8_t*)oe_host_malloc(total_size);
        if (host_buf == NULL)
        {
            TRACE_ENCLAVE(
                "enclave: generate_encrypted_message oe_host_malloc failed.");
            goto exit;
        }

        // Copy the encrypted secret followed by the iv_str and tag_str
        memcpy(host_buf, encrypted_data_buf, encrypted_data_size);
        *size = encrypted_data_size;
        memcpy(&host_buf[*size], iv_str, IV_SIZE);
        *size += IV_SIZE;
        memcpy(&host_buf[*size], tag_str, ENCLAVE_SECRET_DATA_SIZE);
        *size += ENCLAVE_SECRET_DATA_SIZE;

        TRACE_ENCLAVE(
            "enclave: generate_encrypted_message: encrypted_data_size = %ld, "
            "total_size=%ld",
            encrypted_data_size,
            total_size);
        *data = host_buf;
    }
    else
    {
        TRACE_ENCLAVE(
            "enclave: generate_encrypted_message: encrypt_gcm failed\n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

// encrypted_data contains encrypted_data followed by tag_str of equal length
int ecall_dispatcher::process_encrypted_msg(
    uint8_t* encrypted_data,
    size_t encrypted_data_size)
{
    uint8_t data[ENCLAVE_SECRET_DATA_SIZE];
    uint8_t tag_str[ENCLAVE_SECRET_DATA_SIZE];
    size_t data_size = 0;
    uint8_t iv_str[IV_SIZE];
    uint8_t add_str[ADD_SIZE];
    int ret = 1;

    if (m_channel_state != SECURE_CHANNEL_STATE)
    {
        TRACE_ENCLAVE(
            "ecall_dispatcher failed as Secure Channel isn't available.");
        goto exit;
    }

    data_size = sizeof(data);

    memcpy(iv_str, &encrypted_data[ENCLAVE_SECRET_DATA_SIZE], IV_SIZE);
    memcpy(
        tag_str,
        &encrypted_data[ENCLAVE_SECRET_DATA_SIZE + IV_SIZE],
        ENCLAVE_SECRET_DATA_SIZE);

    m_enclave_config->sequence_number++;

    // Convert sequence number to 4 character bytes
    // Since both enclaves are on the same machine, memcpy should suffice
    memset(add_str, 0x00, sizeof(add_str));
    memcpy(add_str, &(m_enclave_config->sequence_number), 4);

    if (m_crypto->decrypt_gcm(
            m_enclave_config->sym_key,
            iv_str,
            add_str,
            encrypted_data,
            ENCLAVE_SECRET_DATA_SIZE,
            tag_str,
            data,
            &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_enclave_config->enclave_secret_data.
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        TRACE_ENCLAVE("Decrypted data: ");
        for (uint32_t i = 0; i < ENCLAVE_SECRET_DATA_SIZE; ++i)
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
        TRACE_ENCLAVE("Enclave:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    TRACE_ENCLAVE("Decrypted data matches with the enclave internal secret "
                  "data: decryption validation succeeded");
    ret = 0;
exit:
    return ret;
}
