// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SAMPLES_TLS_BETWEEN_ENCLAVES_SERVER_TLS_CERT_PRIVATE_KEY_H
#define SAMPLES_TLS_BETWEEN_ENCLAVES_SERVER_TLS_CERT_PRIVATE_KEY_H

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
const char SERVER_ENCLAVE_TLS_CERT_PRIVATE_KEY[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "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\n"
    "-----END RSA PRIVATE KEY-----\n";

#endif /* SAMPLES_TLS_BETWEEN_ENCLAVES_SERVER_TLS_CERT_PRIVATE_KEY_H */
