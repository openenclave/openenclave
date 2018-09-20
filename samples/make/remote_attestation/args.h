// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_REMOTE_ATTESTATION_ARGS_H
#define OE_SAMPLES_REMOTE_ATTESTATION_ARGS_H

// args.h is included by both host and enclave.
// stdint.h is needed for definitions of uint8_t, uint32_t etc.
// In the host, stdint.h is picked up from system includes.
// In the enclave, stdint.h is picked up from openenclave/libc.
#include <stdint.h>

struct remote_report_with_pubkey_t
{
    uint8_t pem_key[512]; // public key information
    uint8_t* remote_report;
    size_t remote_report_size;
};

struct GetRemoteReportWithPubKeyArgs
{
    remote_report_with_pubkey_t* report_with_pub_key; /* out */
    bool success;                                     /* out */
};

struct VerifyReportWithPubKeyArgs
{
    remote_report_with_pubkey_t* report_with_pub_key; /* in */
    bool success;                                     /* out */
};

struct GenerateEncryptedMessageArgs
{
    uint8_t* data; /* out */
    size_t size;   /* out */
    bool success;  /* out */
};

struct ProcessEncryptedMessageArgs
{
    const uint8_t* data; /* in */
    size_t size;         /* in */
    bool success;        /* out */
};

#endif // OE_SAMPLES_REMOTE_ATTESTATION_ARGS_H
