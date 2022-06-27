// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <string.h>
#include "cert_verify_config.h"
#include "utility.h"

oe_result_t claims_verifier_callback(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg);

// If set, the verify callback is called for each certificate in the chain.
// The verification callback is supposed to return 0 on success. Otherwise, the
// verification failed.
int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    oe_result_t result = OE_FAILURE;
    int ret = 1;
    unsigned char* certificate_buffer = nullptr;
    size_t certificate_buffer_size = 0;
    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;

    (void)data;

    printf(TLS_ENCLAVE "Received TLS certificate\n");
    printf(TLS_ENCLAVE "cert_verify_callback with depth = %d\n", depth);

    certificate_buffer = crt->raw.p;
    certificate_buffer_size = crt->raw.len;

    printf(
        TLS_ENCLAVE "crt->version = %d certificate_buffer_size = %zu\n",
        crt->version,
        certificate_buffer_size);

    if (certificate_buffer_size <= 0)
        goto exit;

    result = oe_verify_attestation_certificate_with_evidence_v2(
        certificate_buffer,
        certificate_buffer_size,
        nullptr,
        0,
        nullptr,
        0,
        &claims,
        &claims_length);

    if (result != OE_OK)
    {
        printf(
            TLS_ENCLAVE
            "oe_verify_attestation_certificate_with_evidence_v2 failed "
            "with result = %s\n",
            oe_result_str(result));
        goto exit;
    }

    result = claims_verifier_callback(claims, claims_length, nullptr);

    if (result != OE_OK)
    {
        printf(
            TLS_ENCLAVE "claims_verifier_callback failed with result = %s\n",
            oe_result_str(result));
        goto exit;
    }

    ret = 0;
    *flags = 0;

exit:
    oe_free_claims(claims, claims_length);
    return ret;
}
