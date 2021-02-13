// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../../shared.h"
#include "../fileencryptor_t.h"
#include "encryptor.h"

// Declare a static dispatcher object for enabling for better organization
// of enclave-wise global variables
static ecall_dispatcher dispatcher;

int initialize_encryptor(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
{
    return dispatcher.initialize(encrypt, password, password_len, header);
}

int encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t size)
{
    return dispatcher.encrypt_block(encrypt, input_buf, output_buf, size);
}

void close_encryptor()
{
    return dispatcher.close();
}