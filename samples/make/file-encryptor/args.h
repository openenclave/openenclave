// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#include <openenclave/internal/calls.h>

#define HASH_VALUE_SIZE_IN_BYTES 32
#define ENCRYPTION_KEY_SIZE 256
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)

// EncryptionHeader contains encryption metadata used for decryption
// file_data_size: this is the size of the data in an input file, excluding the
// header digest: this field contains hash value of a password encrypted_key:
// this is the encrypted version of the encryption key used for encrypting and
// decrypting the data
typedef struct _encryption_header
{
    size_t file_data_size;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
} EncryptionHeader;

typedef struct _encrypt_initialize_args
{
    bool do_encrypt;
    const char* password;
    size_t password_len;
    EncryptionHeader* header;
    oe_result_t result;
} EncryptInitializeArgs;

typedef struct _encrypt_block_args
{
    bool do_encrypt;
    unsigned char* inputbuf;
    unsigned char* outputbuf;
    size_t size;
    oe_result_t result;
} EncryptBlockArgs;

typedef struct _close_encryptor_args
{
    bool do_encrypt;
    oe_result_t result;
} CloseEncryptorArgs;

#endif /* _ARGS_H */
