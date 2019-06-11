// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SAMPLES_TLS_BETWEEN_ENCLAVES_CLIENT_TLS_CERT_KEY_H
#define SAMPLES_TLS_BETWEEN_ENCLAVES_CLIENT_TLS_CERT_KEY_H

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Note: an enclave is not supposed to embed any secrets in an enclave
// image itself, such as the TLS private key below.
// In this sample, we focus on showing how to use oe_verify_attestation_cert
// and oe_generate_attestation_cert APIs to establish an attested TLS channel
// . In the real production app, you want to have a clean enclave without
// and secret to start with and once an enclave is running, provision
// secrets into it after the enclave passese attestation challenges from
// the secret owner.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
const char CLIENT_ENCLAVE_TLS_CERT_PRIVATE_KEY[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "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\n"
    "-----END RSA PRIVATE KEY-----\n";

#endif /* SAMPLES_TLS_BETWEEN_ENCLAVES_CLIENT_TLS_CERT_KEYS_H */
