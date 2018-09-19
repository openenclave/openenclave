// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_REMOTE_ATTESTATION_ARGS_H
#define OE_SAMPLES_REMOTE_ATTESTATION_ARGS_H

// args.h is included by both host and enclave.
// stdint.h is needed for definitions of uint8_t, uint32_t etc.
// In the host, stdint.h is picked up from system includes.
// In the enclave, stdint.h is picked up from openenclave/libc.
#include <stdint.h>

struct RemoteReportWithPubKey
{
    uint8_t pemKey[512]; // public key information
    uint8_t* remoteReport;
    size_t remoteReportSize;
};

struct GetRemoteReportWithPubKeyArgs
{
    RemoteReportWithPubKey* reportWithPubKey; /* out */
    bool success;                             /* out */
};

struct VerifyReportWithPubKeyArgs
{
    RemoteReportWithPubKey* reportWithPubKey; /* in */
    bool success;                             /* out */
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
