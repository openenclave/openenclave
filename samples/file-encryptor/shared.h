// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#define HASH_VALUE_SIZE_IN_BYTES 32
#define ENCRYPTION_KEY_SIZE 256
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)

// encryption_header_t contains encryption metadata used for decryption
// file_data_size: this is the size of the data in an input file, excluding the
// header digest: this field contains hash value of a password encrypted_key:
// this is the encrypted version of the encryption key used for encrypting and
// decrypting the data
typedef struct _encryption_header
{
    size_t file_data_size;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
} encryption_header_t;

#endif /* _ARGS_H */
