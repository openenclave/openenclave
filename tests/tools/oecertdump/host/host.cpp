// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oecertdump_u.h"

#if defined(__linux__)
#include <dlfcn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

#include "sgx_quote.h"

#ifdef OE_LINK_SGX_DCAP_QL

#define INPUT_PARAM_OPTION_OUT_FILE "--out"
#define INPUT_PARAM_USAGE "--help"
#define DEFAULT_OUTPUTFILE "oecertdump_out.log"

// Structure to store input parameters
//
typedef struct _input_params
{
    const char* enclave_filename;
    const char* out_filename;
} input_params_t;

static input_params_t _params;

FILE* log_file = NULL;

// This is the identity validation callback. A TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection request
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    OE_UNUSED(arg);
    log("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    log("identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        log("identity.security_version check failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.  In a real scenario,
    // custom id checking should be done here
    log("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        log("0x%0x ", (uint8_t)identity->signer_id[i]);

    log("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        log("0x%0x ", (uint8_t)identity->signer_id[i]);

    log("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        log("0x%0x ", (uint8_t)identity->product_id[i]);
    log("\n");

    result = OE_OK;
done:
    return result;
}

void output_certificate(const uint8_t* data, size_t data_len)
{
#if defined(__linux__)
    if (log_file)
    {
        fprintf(log_file, "\n");
        X509* x509;
        BIO* input = BIO_new_mem_buf(data, (int)data_len);
        x509 = d2i_X509_bio(input, NULL);
        if (x509)
        {
            X509_print_ex_fp(
                log_file, x509, XN_FLAG_COMPAT, XN_FLAG_SEP_CPLUS_SPC);
        }
        BIO_free_all(input);
        fprintf(log_file, "\n");
    }
#endif
    OE_UNUSED(data);
    OE_UNUSED(data_len);
}

void validate_certificate(uint8_t* cert, size_t cert_size)
{
    oe_result_t result;

    result = oe_verify_attestation_certificate(
        cert, cert_size, enclave_identity_verifier, NULL);

    log("Certificate verification result: %s\n", oe_result_str(result));
}

static oe_result_t _gen_cert(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ecall_result;
    unsigned char* cert = NULL;
    size_t cert_size = 0;

    log("========== Getting certificates\n");

    // EC Key
    result = get_tls_cert_signed_with_ec_key(
        enclave, &ecall_result, &cert, &cert_size);
    if ((result != OE_OK) || (ecall_result != OE_OK))
    {
        log("Failed to create EC certificate. Enclave: %s, Host: %s\n",
            oe_result_str(ecall_result),
            oe_result_str(result));

        goto exit;
    }
    else
    {
        output_certificate(cert, cert_size);
        validate_certificate(cert, cert_size);
    }
    if (cert)
    {
        free(cert);
        cert = NULL;
    }
    cert_size = 0;

    // RSA Key
    result = get_tls_cert_signed_with_rsa_key(
        enclave, &ecall_result, &cert, &cert_size);
    if ((result != OE_OK) || (ecall_result != OE_OK))
    {
        log("Failed to create RSA certificate. Enclave: %s, Host: %s\n",
            oe_result_str(ecall_result),
            oe_result_str(result));

        goto exit;
    }
    else
    {
        output_certificate(cert, cert_size);
        validate_certificate(cert, cert_size);
    }

exit:
    // deallcate resources
    if (cert)
        free(cert);

    return result;
}

static void _display_help(const char* cmd)
{
    printf("Usage: %s ENCLAVE_PATH Options\n", cmd);
    printf("\tOptions:\n");
    printf("\t%s : output filename.\n", INPUT_PARAM_OPTION_OUT_FILE);
}

static int _parse_args(int argc, const char* argv[])
{
    if (argc < 1)
    {
        _display_help(argv[0]);
        return 1;
    }

    // clear params memory
    memset(&_params, 0, sizeof(_params));

    int i = 1; // current index
    // save
    _params.enclave_filename = argv[i++];
    _params.out_filename = DEFAULT_OUTPUTFILE;

    // Verify enclave file is valid
    FILE* fp;
#ifdef _WIN32
    fopen_s(&fp, _params.enclave_filename, "rb");
#else
    fp = fopen(_params.enclave_filename, "rb");
#endif
    if (!fp)
    {
        printf("Failed to find file: %s\n", _params.enclave_filename);
        return 1;
    }
    else
        fclose(fp);

    while (i < argc)
    {
        if (strcmp(INPUT_PARAM_OPTION_OUT_FILE, argv[i]) == 0)
        {
            if (argc >= i + 1)
            {
                _params.out_filename = argv[i + 1];
                i += 2;
            }
            else
            {
                printf(
                    "%s has invalid number of parameters.\n",
                    INPUT_PARAM_OPTION_OUT_FILE);
                _display_help(argv[0]);
                return 1;
            }
        }
        else if (strcmp(INPUT_PARAM_USAGE, argv[i]) == 0)
        {
            _display_help(argv[0]);
            return 1;
        }
        else
        {
            printf("Invalid option: %s\n", argv[i]);
            return 1;
        }
    }

    return 0;
}

static oe_result_t _process_params(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;

    result = gen_report(enclave);
    if (result != OE_OK)
        return result;

    result = _gen_cert(enclave);

    return result;
}

#endif // OE_LINK_SGX_DCAP_QL

int main(int argc, const char* argv[])
{
    int ret = 0;

#ifdef OE_LINK_SGX_DCAP_QL
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("oecertdump not supported in simulation mode.\n");
        goto exit;
    }

    ret = _parse_args(argc, argv);
    if (ret != 0)
        goto exit;

    if ((result = oe_create_oecertdump_enclave(
             _params.enclave_filename,
             OE_ENCLAVE_TYPE_AUTO,
             OE_ENCLAVE_FLAG_DEBUG,
             NULL,
             0,
             &enclave)) != OE_OK)
    {
        printf(
            "Failed to create enclave. result=%u (%s)\n",
            result,
            oe_result_str(result));
        ret = 1;
        goto exit;
    }

    // Create log file
#ifdef _WIN32
    fopen_s(&log_file, _params.out_filename, "w");
#else
    log_file = fopen(_params.out_filename, "w");
#endif
    if (!log_file)
    {
        printf("Failed to open log file %s\n", _params.out_filename);
        ret = 1;
        goto exit;
    }

    set_log_callback();

    if ((result = _process_params(enclave)) != OE_OK)
    {
        printf(
            "Failed to process parameters. result=%u (%s)\n",
            result,
            oe_result_str(result));
        ret = 1;
        goto exit;
    }

    printf(
        "oecertdump succeeded. Log file %s created.\n", _params.out_filename);

exit:
    if (enclave)
        oe_terminate_enclave(enclave);

    if (log_file)
    {
        fflush(log_file);
        fclose(log_file);
    }

#else
#pragma message( \
    "OE_LINK_SGX_DCAP_QL is not set to ON.  This tool requires DCAP libraries.")
    OE_UNUSED(argc);
    OE_UNUSED(argv);
    printf("oecertdump requires DCAP libraries.\n");
#endif
    return ret;
}
