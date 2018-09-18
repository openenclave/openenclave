// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <string>
#include "../args.h"

using namespace std;

#define IV_SIZE 16

class ECallDispatcher
{
  private:
    mbedtls_aes_context m_aescontext;
    bool m_bEncrypt;
    string m_Password;

    EncryptionHeader* m_pHeader;

    // initialization vector
    unsigned char m_original_iv[IV_SIZE];
    unsigned char m_operating_iv[IV_SIZE];

    // key for encrypting  data
    unsigned char m_encryption_key[ENCRYPTION_KEY_SIZE_IN_BYTES];

  public:
    ECallDispatcher();
    void Initialize(EncryptInitializeArgs* args);
    void EncryptBlock(EncryptBlockArgs* args);
    void close(CloseEncryptorArgs* args);

  private:
    int generatePasswordKey(
        const char* _password,
        unsigned char* _key,
        unsigned int _keyLength);

    int generateEncryptionKey(unsigned char* _key, unsigned int _keyLength);

    int cipherEncryptionKey(
        bool bEncrypt,
        unsigned char* pInputData,
        unsigned int inputDataSize,
        unsigned char* encryptKey,
        unsigned char* pOutData,
        unsigned int outputDataSize);

    int prepareEncryptionHeader(EncryptionHeader* pHeader, string password);
    int parseEncryptionHeader(EncryptionHeader* pHeader, string password);

    int Sha256(const uint8_t* data, size_t dataSize, uint8_t sha256[32]);
    void dumpData(const char* name, unsigned char* pData, size_t dataSize);
    int processEncryptionHeader(EncryptInitializeArgs* args);
};
