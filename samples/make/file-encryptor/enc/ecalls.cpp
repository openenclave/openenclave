// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../args.h"
#include "encryptor.h"
#include "fileencryptor_t.h"

// Declare a static dispatcher object for enabling for better organization
// enclave-wise global variables
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
    unsigned char* inputbuf,
    unsigned char* outputbuf,
    size_t size)
{
    return dispatcher.encrypt_block(encrypt, inputbuf, outputbuf, size);
}

void close_encryptor()
{
    return dispatcher.close();
}
