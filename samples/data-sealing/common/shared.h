// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SHARED_H
#define _SHARED_H

#include <stddef.h>

#define POLICY_UNIQUE 1
#define POLICY_PRODUCT 2

#define MAX_OPT_MESSAGE_LEN 128
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
    size_t total_size;
    unsigned char signature[SIGNATURE_LEN];
    unsigned char opt_msg[MAX_OPT_MESSAGE_LEN];
    unsigned char iv[IV_SIZE];
    size_t key_info_size;
    size_t original_data_size;
    size_t encrypted_data_len;
    unsigned char encrypted_data[1];
} sealed_data_t;

#endif /* _SHARED_H */
