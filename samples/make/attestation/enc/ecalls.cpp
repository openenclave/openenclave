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

    uint8_t pemPublicKey[512];
    GetPublicKey(pemPublicKey);

    // Generate a quote for the public key so that the enclave that receives the
    // key can attest this enclave. It is safer to use enclave memory for all
    // operations within the enclave. A malicious host could tamper with host
    // memory while enclave is processing it.
    uint8_t* quote = new uint8_t[OE_MAX_REPORT_SIZE];
    size_t quoteSize = OE_MAX_REPORT_SIZE;

    if (GenerateQuote(pemPublicKey, sizeof(pemPublicKey), quote, &quoteSize))
    {
        // Copy the quote to the host memory.
        uint8_t* hostQuote = (uint8_t*)oe_host_malloc(quoteSize);
        memcpy(hostQuote, quote, quoteSize);

        // Create return parameter.
        QuotedPublicKey* quotedPublicKey =
            (QuotedPublicKey*)oe_host_malloc(sizeof(QuotedPublicKey));
        memcpy(quotedPublicKey->pemKey, pemPublicKey, sizeof(pemPublicKey));
        quotedPublicKey->quote = hostQuote;
        quotedPublicKey->quoteSize = quoteSize;

        arg->quotedPublicKey = quotedPublicKey;
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
uint8_t g_OtherEnclavePemPublicKey[512];

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
    StorePublicKeyArgs encArg = *arg;

    QuotedPublicKey quotedPublicKey = *encArg.quotedPublicKey;
    if (!quotedPublicKey.quote ||
        !oe_is_outside_enclave(
            quotedPublicKey.quote, quotedPublicKey.quoteSize))
        return;

    uint8_t* quote = new uint8_t[quotedPublicKey.quoteSize];
    memcpy(quote, quotedPublicKey.quote, quotedPublicKey.quoteSize);

    // Attest the quote and accompanying key.
    if (AttestQuote(
            quote,
            quotedPublicKey.quoteSize,
            quotedPublicKey.pemKey,
            sizeof(quotedPublicKey.pemKey)))
    {
        memcpy(
            g_OtherEnclavePemPublicKey,
            quotedPublicKey.pemKey,
            sizeof(g_OtherEnclavePemPublicKey));

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
// g_TestData (encrypted) to the second enclave. The second enclave decrypts the
// received data and adds it to its own g_TestData, and sends it back to the
// first enclave.
uint8_t g_TestData[16] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

/**
 * Generate encrypted data using stored public key of other enclave.
*/
OE_ECALL void GenerateEncryptedData(GenerateEncryptedDataArgs* arg)
{
    // ECALL parameters must lie outside the enclave.
    if (!arg || !oe_is_outside_enclave(arg, sizeof(*arg)))
        return;

    uint8_t encryptedDataBuffer[1024];
    size_t encryptedDataSize = sizeof(encryptedDataBuffer);
    if (Encrypt(
            g_OtherEnclavePemPublicKey,
            g_TestData,
            sizeof(g_TestData),
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
    ProcessEncryptedDataArgs encArg = *arg;

    if (!encArg.data || !oe_is_outside_enclave(encArg.data, encArg.size))
        return;

    uint8_t* encryptedData = new uint8_t[encArg.size];
    memcpy(encryptedData, encArg.data, encArg.size);

    uint8_t data[16];
    size_t dataSize = sizeof(data);

    if (Decrypt(encryptedData, encArg.size, data, &dataSize))
    {
        // Print decrypted values to illustrate arbitrary operations on the
        // data.
        printf("Decrypted data: ");
        for (uint32_t i = 0; i < dataSize; ++i)
        {
            g_TestData[i] += data[i];
            printf("%d ", data[i]);
        }
        printf("\n");
        arg->success = true;
    }
    else
    {
        arg->success = false;
    }
    delete[] encryptedData;
}
