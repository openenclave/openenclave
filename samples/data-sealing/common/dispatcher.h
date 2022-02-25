// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <openenclave/enclave.h>
#include <openenclave/seal.h>
#include <string>
#include "datasealing_args.h"
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
        data_t* sealed_data);

    int unseal_data(const data_t* sealed_data, data_t* output_data);

  private:
    void dump_data(const char* name, unsigned char* data, size_t data_size);
};
