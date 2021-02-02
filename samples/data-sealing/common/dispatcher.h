// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <openenclave/enclave.h>
#include <openenclave/seal.h>
#include <string>
#include "shared.h"

using namespace std;

#define SEAL_KEY_SIZE 16
#define CIPHER_BLOCK_SIZE 16
#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false
#define HASH_VALUE_SIZE_IN_BYTES 32

class ecall_dispatcher
{
  public:
    // two ecalls
    int seal_data(
        int seal_policy,
        const unsigned char* opt_mgs,
        size_t opt_msg_len,
        const unsigned char* data,
        size_t data_size,
        sealed_data_t** sealed_data,
        size_t* sealed_data_size);

    int unseal_data(
        const sealed_data_t* sealed_data,
        size_t sealed_data_size,
        unsigned char** data,
        size_t* data_size);

  private:
    void dump_data(const char* name, unsigned char* data, size_t data_size);
};
