// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <errno.h>
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <openenclave/enclave.h>
#include <string.h>
#include "../../common/tls_client_tls_cert_private_key.h"
#include "../../common/tls_client_tls_cert_public_key.h"
#include "../../common/tls_server_tls_cert_public_key.h"
#include "../../common/utility.h"

oe_result_t enclave_identity_verifier_callback(
    oe_identity_t* identity,
    void* arg);

oe_result_t get_tls_cert_keys(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size)
{
    *public_key = (uint8_t*)CLIENT_ENCLAVE_TLS_CERT_PUBLIC_KEY;
    *public_key_size = strlen(CLIENT_ENCLAVE_TLS_CERT_PUBLIC_KEY) + 1;
    *private_key = (uint8_t*)CLIENT_ENCLAVE_TLS_CERT_PRIVATE_KEY;
    *private_key_size = strlen(CLIENT_ENCLAVE_TLS_CERT_PRIVATE_KEY) + 1;

    return OE_OK;
}

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

    printf(" cert_verify_callback with depth = %d\n", depth);

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    printf("crt->version = %d cert_size = %zu\n", crt->version, cert_size);
    if (cert_size <= 0)
        goto exit;

    // The following two checked
    if (!is_certificate_public_key_trusted(
            crt,
            (char*)SERVER_ENCLAVE_TLS_CERT_PUBLIC_KEY,
            strlen(SERVER_ENCLAVE_TLS_CERT_PUBLIC_KEY)))
    {
        printf("Unexpected certificate received\n");
        printf("Expected: [%s]\n", (char*)SERVER_ENCLAVE_TLS_CERT_PUBLIC_KEY);
        goto exit;
    }

    result = oe_verify_attestation_certificate(
        cert_buf, cert_size, enclave_identity_verifier_callback, NULL);
    if (result != OE_OK)
    {
        printf(
            "oe_verify_attestation_certificate failed with result = %s\n",
            oe_result_str(result));
        goto exit;
    }
    ret = 0;
    *flags = 0;
exit:
    return ret;
}