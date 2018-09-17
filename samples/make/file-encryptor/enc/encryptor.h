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
    bool m_b_encrypt;
    string m_password;

    EncryptionHeader* m_p_header;

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
    int generate_password_key(
        const char* _password,
        unsigned char* _key,
        unsigned int _key_length);

    int generate_encryption_key(unsigned char* _key, unsigned int _key_length);

    int cipher_encryption_key(
        bool do_encrypt,
        unsigned char* input_data,
        unsigned int input_data_size,
        unsigned char* encrypt_key,
        unsigned char* out_data,
        unsigned int output_data_size);

    int prepare_encryption_header(EncryptionHeader* header, string password);
    int parse_encryption_header(EncryptionHeader* header, string password);

    int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32]);
    void dump_data(const char* name, unsigned char* data, size_t data_size);
    int process_encryption_header(EncryptInitializeArgs* args);
};
