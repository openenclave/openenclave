// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#include <openenclave/internal/calls.h>

#define HASH_VALUE_SIZE_IN_BYTES 32
#define ENCRYPTION_KEY_SIZE 256
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)

// EncryptionHeader contains encryption metadata used for decryption
// fileDataSize: this is the size of the data in an input file, excluding the
// header digest: this field contains hash value of a password encryptedKey:
// this is the encrypted version of the encryption key used for encrypting and
// decrypting the data
typedef struct _EncryptionHeader
{
    size_t fileDataSize;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char encryptedKey[ENCRYPTION_KEY_SIZE_IN_BYTES];
} EncryptionHeader;

typedef struct _EncryptInitializeArgs
{
    bool bEncrypt;
    const char* password;
    size_t passwordLen;
    EncryptionHeader* pHeader;
    oe_result_t result;
} EncryptInitializeArgs;

typedef struct _EncryptBlockArgs
{
    bool bEncrypt;
    unsigned char* inputbuf;
    unsigned char* outputbuf;
    size_t size;
    oe_result_t result;
} EncryptBlockArgs;

typedef struct _CloseEncryptorArgs
{
    bool bEncrypt;
    oe_result_t result;
} CloseEncryptorArgs;

#endif /* _ARGS_H */
