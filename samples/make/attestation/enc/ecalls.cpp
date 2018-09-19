// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <string.h>

#include "attestation.h"
#include "crypto.h"
#include "ecalls.h"
#include "log.h"

/**
 * Return the public key of this enclave along with the enclave's quote.
 * The enclave that receives the key will use the quote to attest this enclave.
 */
OE_ECALL void GetPublicKey(GetPublicKeyArgs* arg)
{
    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        return;

    uint8_t pem_public_key[512];
    GetPublicKey(pem_public_key);

    // Generate a quote for the public key so that the enclave that receives the
    // key can attest this enclave. It is safer to use enclave memory for all
    // operations within the enclave. A malicious host could tamper with host
    // memory while enclave is processing it.
    uint8_t* quote = new uint8_t[OE_MAX_REPORT_SIZE];
    size_t quote_size = OE_MAX_REPORT_SIZE;

    if (GenerateQuote(
            pem_public_key, sizeof(pem_public_key), quote, &quote_size))
    {
        // Copy the quote to the host memory.
        uint8_t* host_quote = (uint8_t*)oe_host_malloc(quote_size);
        memcpy(host_quote, quote, quote_size);

        // Create return parameter.
        QuotedPublicKey* quoted_public_key =
            (QuotedPublicKey*)oe_host_malloc(sizeof(QuotedPublicKey));
        memcpy(
            quoted_public_key->pem_key, pem_public_key, sizeof(pem_public_key));
        quoted_public_key->quote = host_quote;
        quoted_public_key->quote_size = quote_size;

        arg->quoted_public_key = quoted_public_key;
        arg->success = true;

        ENC_DEBUG_PRINTF("GetPublicKey succeeded.");
    }
    else
    {
        ENC_DEBUG_PRINTF("GetPublicKey failed.");
        arg->success = false;
    }

    delete[] quote;
}

// Public key of another enclave.
uint8_t g_other_enclave_pem_public_key[512];

/**
 * Attest and store the public key of another enclave.
 */
OE_ECALL void StorePublicKey(StorePublicKeyArgs* arg)
{
    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        return;

    arg->success = false;

    // It is safer to use enclave memory for all operations within the enclave.
    // A malicious host could tamper with host memory while enclave is
    // processing it. Perform deep copy of argument.
    StorePublicKeyArgs enc_arg = *arg;

    QuotedPublicKey quoted_public_key = *enc_arg.quoted_public_key;
    if (!quoted_public_key.quote ||
        !oe_is_outside_enclave(
            quoted_public_key.quote, quoted_public_key.quote_size))
        return;

    uint8_t* quote = new uint8_t[quoted_public_key.quote_size];
    memcpy(quote, quoted_public_key.quote, quoted_public_key.quote_size);

    // Attest the quote and accompanying key.
    if (AttestQuote(
            quote,
            quoted_public_key.quote_size,
            quoted_public_key.pem_key,
            sizeof(quoted_public_key.pem_key)))
    {
        memcpy(
            g_other_enclave_pem_public_key,
            quoted_public_key.pem_key,
            sizeof(g_other_enclave_pem_public_key));

        arg->success = true;
        ENC_DEBUG_PRINTF("StorePublicKey succeeded.");
    }
    else
    {
        ENC_DEBUG_PRINTF("StorePublicKey failed.");
        arg->success = false;
    }

    delete[] quote;
}

// Arbitrary test data exchanged by the enclaves. The first enclave sends its
// g_test_data (encrypted) to the second enclave. The second enclave decrypts
// the
// received data and adds it to its own g_test_data, and sends it back to the
// first enclave.
uint8_t g_test_data[16] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

/**
 * Generate encrypted data using stored public key of other enclave.
*/
OE_ECALL void GenerateEncryptedData(GenerateEncryptedDataArgs* arg)
{
    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        return;

    uint8_t encrypted_data_buffer[1024];
    size_t encrypted_data_size = sizeof(encrypted_data_buffer);
    if (Encrypt(
            g_other_enclave_pem_public_key,
            g_test_data,
            sizeof(g_test_data),
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
}

/**
 * Process encrypted data.
*/
OE_ECALL void ProcessEncryptedData(ProcessEncryptedDataArgs* arg)
{
    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        return;

    arg->success = false;

    // It is safer to use enclave memory for all operations within the enclave.
    // A malicious host could tamper with host memory while enclave is
    // processing it. Perform deep copy of argument.
    ProcessEncryptedDataArgs enc_arg = *arg;

    if (!enc_arg.data || !oe_is_outside_enclave(enc_arg.data, enc_arg.size))
        return;

    uint8_t* encrypted_data = new uint8_t[enc_arg.size];
    memcpy(encrypted_data, enc_arg.data, enc_arg.size);

    uint8_t data[16];
    size_t data_size = sizeof(data);

    if (Decrypt(encrypted_data, enc_arg.size, data, &data_size))
    {
        // Print decrypted values to illustrate arbitrary operations on the
        // data.
        printf("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            g_test_data[i] += data[i];
            printf("%d ", data[i]);
        }
        printf("\n");
        arg->success = true;
    }
    else
    {
        arg->success = false;
    }
    delete[] encrypted_data;
}
