// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "../../common/utility.h"

oe_result_t enclave_claims_verifier_callback(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg);

// The server end of this established is inside an enclave. If the connecting
// client provides a certificate during the TLS handshaking,
// cert_verify_callback will be called with client's certificate. When everthing
// is validated successfully, mainly passing
// oe_verify_attestation_certificate_with_evidence(), we can be sure the
// established TLS channel is an Attested TLS channel between two enclaves. In
// the case of establishing an Attested TLS channel between an non-enclave
// client and enclave, cert_verify_callback won't be called in our sample.
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

    printf(TLS_SERVER
           "\n** Received client certificate and started validating it**\n\n");
    printf(TLS_SERVER "cert_verify_callback with depth = %d\n", depth);

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    printf(
        TLS_SERVER "crt->version = %d cert_size = %zu\n",
        crt->version,
        cert_size);

    if (cert_size <= 0)
        goto exit;

    result = oe_verify_attestation_certificate_with_evidence(
        cert_buf, cert_size, enclave_claims_verifier_callback, NULL);
    if (result != OE_OK)
    {
        printf(
            TLS_SERVER "oe_verify_attestation_certificate_with_evidence failed "
                       "with result = %s\n",
            oe_result_str(result));
        goto exit;
    }
    ret = 0;
    *flags = 0;
    printf(TLS_SERVER "\n\n---------Establishing an Attested TLS channel "
                      "between two enclaves---------\n\n");
exit:
    return ret;
}
