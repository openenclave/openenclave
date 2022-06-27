// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#define HASH_VALUE_SIZE_IN_BYTES 32 // sha256 hashing algorithm
#define ENCRYPTION_KEY_SIZE 256     // AES256-CBC encryption algorithm
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
#define IV_SIZE 16 // determined by AES256-CBC
#define SALT_SIZE_IN_BYTES IV_SIZE

// encryption_header_t contains encryption metadata used for decryption
// file_data_size: this is the size of the data in an input file, excluding the
// header digest: this field contains hash value of a password
// encrypted_key: this is the encrypted version of the encryption key used for
//                encrypting and decrypting the data
// salt: The salt value used in deriving the password key.
//       It is also used as the IV for the encryption/decryption of the data.
typedef struct _encryption_header
{
    size_t file_data_size;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
    unsigned char salt[SALT_SIZE_IN_BYTES];
} encryption_header_t;

#endif /* _ARGS_H */
