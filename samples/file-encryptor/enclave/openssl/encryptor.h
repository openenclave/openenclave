// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <openenclave/enclave.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>
#include "../../shared.h"

using namespace std;

#define IV_SIZE 16

class ecall_dispatcher
{
  private:
    EVP_CIPHER_CTX* m_encryption_cipher_ctx;
    EVP_CIPHER_CTX* m_decryption_cipher_ctx;
    bool m_encrypt;
    string m_password;

    encryption_header_t* m_header;

    // initialization vector
    unsigned char m_original_iv[IV_SIZE];

    // key for encrypting data
    unsigned char m_encryption_key[ENCRYPTION_KEY_SIZE_IN_BYTES];

  public:
    ecall_dispatcher();
    int initialize(
        bool encrypt,
        const char* password,
        size_t password_len,
        encryption_header_t* header);
    int encrypt_block(
        bool encrypt,
        unsigned char* input_buf,
        unsigned char* output_buf,
        size_t size);
    void close();

  private:
    int generate_password_key(
        const char* password,
        unsigned char* key,
        unsigned int key_len);
    int generate_encryption_key(unsigned char* key, unsigned int key_len);
    int prepare_encryption_header(encryption_header_t* header, string password);
    int parse_encryption_header(encryption_header_t* header, string password);
    int cipher_encryption_key(
        bool encrypt,
        unsigned char* input_data,
        unsigned int input_data_size,
        unsigned char* encrypt_key,
        unsigned char* output_data,
        int output_data_size);
    int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32]);
    void dump_data(const char* name, unsigned char* data, size_t data_size);
    int process_encryption_header(
        bool encrypt,
        const char* password,
        size_t password_len,
        encryption_header_t* header);
};
