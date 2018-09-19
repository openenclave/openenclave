// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ARGS_H
#define OE_SAMPLES_ATTESTATION_ARGS_H

// args.h is included by both host and enclave.
// stdint.h is needed for definitions of uint8_t, uint32_t etc.
// In the host, stdint.h is picked up from system includes.
// In the enclave, stdint.h is picked up from openenclave/libc.
#include <stdint.h>

struct QuotedPublicKey
{
    uint8_t pemKey[512];
    uint8_t* quote;
    size_t quoteSize;
};

struct GetPublicKeyArgs
{
    QuotedPublicKey* quotedPublicKey; /* out */
    bool success;                     /* out */
};

struct StorePublicKeyArgs
{
    QuotedPublicKey* quotedPublicKey; /* in */
    bool success;                     /* out */
};

struct GenerateEncryptedDataArgs
{
    uint8_t* data; /* out */
    size_t size;   /* out */
    bool success;  /* out */
};

struct ProcessEncryptedDataArgs
{
    const uint8_t* data; /* in */
    size_t size;         /* in */
    bool success;        /* out */
};

#endif // OE_SAMPLES_ATTESTATION_ARGS_H
