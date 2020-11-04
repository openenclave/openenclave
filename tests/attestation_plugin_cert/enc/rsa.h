// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#define OE_RSA_PUBLIC_KEY_SIZE 512
#define OE_RSA_PRIVATE_KEY_SIZE 2048

oe_result_t generate_rsa_pair(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size);
