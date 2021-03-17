// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SHARED_H
#define _SHARED_H

#include <stddef.h>

#define POLICY_UNIQUE 1
#define POLICY_PRODUCT 2

#define MAX_OPTIONAL_MESSAGE_SIZE 128
#define IV_SIZE 16
#define SIGNATURE_LEN 32

// errors shared by host and enclaves
#define ERROR_SIGNATURE_VERIFY_FAIL 1
#define ERROR_OUT_OF_MEMORY 2
#define ERROR_GET_SEALKEY 3
#define ERROR_SIGN_SEALED_DATA_FAIL 4
#define ERROR_CIPHER_ERROR 5
#define ERROR_UNSEALED_DATA_FAIL 6
#define ERROR_SEALED_DATA_FAIL 7
#define ERROR_INVALID_PARAMETER 8

typedef struct _sealed_data_t
{
    unsigned char optional_message[MAX_OPTIONAL_MESSAGE_SIZE];
    size_t sealed_blob_size;
} sealed_data_t;

#endif /* _SHARED_H */
