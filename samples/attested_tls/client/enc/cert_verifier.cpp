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
#include "../../common/utility.h"

oe_result_t enclave_claims_verifier_callback(
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
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;

    printf(TLS_CLIENT "Received TLS certificate from server\n");
    printf(TLS_CLIENT "cert_verify_callback with depth = %d\n", depth);

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    printf(
        TLS_CLIENT "crt->version = %d cert_size = %zu\n",
        crt->version,
        cert_size);

    if (cert_size <= 0)
        goto exit;

    result = oe_verify_attestation_certificate_with_evidence(
        cert_buf, cert_size, enclave_claims_verifier_callback, NULL);
    if (result != OE_OK)
    {
        printf(
            TLS_CLIENT "oe_verify_attestation_certificate_with_evidence failed "
                       "with result = %s\n",
            oe_result_str(result));
        goto exit;
    }
    ret = 0;
    *flags = 0;
exit:
    return ret;
}