#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl_cache.h>
#include "common.h"

tls_control_args_t g_control_config;

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    int ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;

    *flags = (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    if (g_control_config.fail_cert_verify_callback)
        goto done;

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

#if 0
    OE_TRACE_INFO("cert_verify_callback with depth = %d\n", depth);
    OE_TRACE_INFO("crt->version = %d\n", crt->version);
    OE_TRACE_INFO("cert_size = %zu\n", cert_size);
#endif

    if (cert_size <= 0)
        goto done;

#if 0
    OE_TRACE_INFO("Calling oe_verify_attestation_certificate\n");
#endif
    if (g_control_config.fail_oe_verify_attestation_certificate)
        goto done;

    result = oe_verify_attestation_certificate(
        cert_buf, cert_size, enclave_identity_verifier, NULL);
    OE_CHECK_MSG(
        result,
        "oe_verify_attestation_certificate failed with result = %s\n",
        oe_result_str(result));

    OE_TRACE_INFO("\nReturned from oe_verify_attestation_certificate\n");
    ret = 0;
    *flags = 0;
done:
    return ret;
}
