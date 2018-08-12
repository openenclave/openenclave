// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "../args.h"


#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define IV_SIZE 16
#define ENCRYPTION_KEY_SIZE_IN_BYTES 32
#define ENCRYPTION_KEY_SIZE 256

class Encryptor
{
  private:
      char* m_password; 

      mbedtls_aes_context      m_aescontext;
      mbedtls_ctr_drbg_context m_ctldrbgcontext;
      mbedtls_entropy_context  m_entropycontext;


      unsigned char m_inputbuf[128] = {0};
      unsigned char m_outputbuf[128] = {0};

      // iv
      unsigned char m_original_iv[IV_SIZE];
      unsigned char m_operating_iv[IV_SIZE];


      // key
      unsigned char m_encryption_key[ENCRYPTION_KEY_SIZE_IN_BYTES];

public:

  Encryptor();

  void set_password(PasswordArgs* args);
  void initialize(EncryptArgs* args);
  void encryt_block(EncryptBlockArgs* args);
  void close(CloseEncryptorArgs* args);

private:

  void generate_aes_key(char *_password, unsigned char *_key, unsigned int _length);

};


