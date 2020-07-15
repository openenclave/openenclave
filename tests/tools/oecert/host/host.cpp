// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oecert_u.h"

#include "../../../../common/sgx/endorsements.h"

#ifdef OE_HAS_SGX_DCAP_QL

#define INPUT_PARAM_OPTION_CERT "--cert"
#define INPUT_PARAM_OPTION_REPORT "--report"
#define INPUT_PARAM_OPTION_OUT_FILE "--out"

// Structure to store input parameters
//
typedef struct _input_params
{
    const char* enclave_filename;
    const char* private_key_filename;
    const char* public_key_filename;
    const char* out_filename;
    bool gen_cert;
    bool gen_report;
} input_params_t;

static input_params_t _params;

// This is the identity validation callback. An TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection request
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    printf("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    printf("identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        printf(
            "identity.security_version check failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.  In a real scenario,
    // custom id checking should be done here
    printf("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);

    printf("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);

    printf("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

static oe_result_t _gen_cert(
    oe_enclave_t* enclave,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    const char* out_filename)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ecall_result;
    unsigned char* cert = NULL;
    size_t cert_size = 0;

    printf("Creating certificate with given private/public keys.\n");
    result = get_tls_cert_signed_with_key(
        enclave,
        &ecall_result,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        &cert,
        &cert_size);

    if ((result != OE_OK) || (ecall_result != OE_OK))
    {
        printf(
            "Failed to create certificate. Enclave: %s, Host: %s\n",
            oe_result_str(ecall_result),
            oe_result_str(result));
        fflush(stdout);
        goto exit;
    }

    {
        // output the whole cer in DER format
        FILE* file = NULL;

        printf("Creating certificate file: %s\n", out_filename);
#ifdef _WIN32
        fopen_s(&file, out_filename, "wb");
#else
        file = fopen(out_filename, "wb");
#endif
        if (file == NULL)
        {
            printf("Failed to open file: %s\n", out_filename);
            goto exit;
        }
        fwrite(cert, 1, cert_size, file);
        fclose(file);
    }

    {
        // TODO: Dump cert
    }

    // validate cert
    printf("cert = %p cert_size = %zu\n", cert, cert_size);
    result = oe_verify_attestation_certificate(
        cert, cert_size, enclave_identity_verifier, NULL);
    printf(
        "Verifying the certificate from a host ... %s\n",
        result == OE_OK ? "Success" : "Fail");
    fflush(stdout);

exit:
    // deallcate resources
    if (cert)
        free(cert);

    return result;
}

static oe_result_t _gen_report(
    oe_enclave_t* enclave,
    const char* report_filename)
{
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = NULL;
    oe_result_t result = oe_get_report(
        enclave,
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL, // opt_params must be null
        0,
        (uint8_t**)&remote_report,
        &report_size);
    if (result == OE_OK)
    {
        printf("oe_get_report succeeded report_size = %zu\n", report_size);

        // Write report to file
        {
            FILE* output = NULL;
#ifdef _WIN32
            fopen_s(&output, report_filename, "wb");
#else
            output = fopen(report_filename, "wb");
#endif
            if (!output)
            {
                printf("Failed to open report file %s\n", report_filename);
                result = OE_FAILURE;
                goto exit;
            }
            fwrite(remote_report, report_size, 1, output);
            fclose(output);
            printf("report_size = %zu\n", report_size);
        }

        // Verify report
        {
            oe_report_t parsed_report;
            result = oe_verify_report(
                NULL, remote_report, report_size, &parsed_report);
            if (result != OE_OK)
            {
                printf(
                    "Failed to verify report. result=%u (%s)\n",
                    result,
                    oe_result_str(result));
                goto exit;
            }
            else
            {
                // TODO: Dump report.
            }
        }

        char collateral_filename[1024 + 1];

        if (strlen(report_filename) < (1024 - 4))
        {
            uint8_t* collaterals = NULL;
            size_t collaterals_size = 0;
            oe_report_header_t* header = (oe_report_header_t*)remote_report;

            sprintf_s(
                collateral_filename,
                sizeof(collateral_filename),
                "%s.col",
                report_filename);
            printf("Generatting collateral file: %s\n", collateral_filename);

            result = oe_get_sgx_endorsements(
                header->report,
                header->report_size,
                &collaterals,
                &collaterals_size);
            if (result != OE_OK)
            {
                printf("Failed to create SGX endorsements.");
                result = OE_FAILURE;
                goto exit;
            }

            FILE* col_fp;
#ifdef _WIN32
            fopen_s(&col_fp, collateral_filename, "wb");
#else
            col_fp = fopen(collateral_filename, "wb");
#endif
            if (!col_fp)
            {
                printf(
                    "Failed to open collateral file %s\n", collateral_filename);
                result = OE_FAILURE;
                goto exit;
            }
            fwrite(collaterals, collaterals_size, 1, col_fp);
            fclose(col_fp);
            printf("collaterals_size = %zu\n", collaterals_size);
        }
        else
        {
            printf("ERROR: Report filename is too long.\n");
            exit(1);
        }
    }
    else
    {
        printf("Failed to create report. Error: %s\n", oe_result_str(result));
    }
exit:

    if (remote_report)
        oe_free_report(remote_report);

    return result;
}

static void _display_help(const char* cmd)
{
    printf("Usage: %s ENCLAVE_PATH Options\n", cmd);
    printf("\tOptions:\n");
    printf(
        "\t%s PRIVKEY PUBKEY: generate der remote attestation certificate.\n",
        INPUT_PARAM_OPTION_CERT);
    printf(
        "\t%s : generate binary enclave evidence and endorsements.\n",
        INPUT_PARAM_OPTION_REPORT);
    printf("\t%s : output filename.\n", INPUT_PARAM_OPTION_OUT_FILE);

    // TODO: Add option to display certs
    // TODO: Add option to create pem version of the certs.
}

static int _parse_args(int argc, const char* argv[])
{
    if (argc < 3)
    {
        _display_help(argv[0]);
        return 1;
    }

    // clear params memory
    memset(&_params, 0, sizeof(_params));
    _params.gen_report = false;
    _params.gen_cert = false;

    int i = 1; // current index
    // save
    _params.enclave_filename = argv[i++];
    _params.out_filename = "out.bin";

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
        if (strcmp(INPUT_PARAM_OPTION_CERT, argv[i]) == 0)
        {
            if (argc >= (i + 2))
            {
                _params.gen_cert = true;
                _params.private_key_filename = argv[i + 1];
                _params.public_key_filename = argv[i + 2];

                i += 3;
            }
            else
            {
                printf(
                    "%s has invalid number of parameters.\n",
                    INPUT_PARAM_OPTION_CERT);
                _display_help(argv[0]);
                return 1;
            }
        }
        else if (strcmp(INPUT_PARAM_OPTION_REPORT, argv[i]) == 0)
        {
            if (argc >= i)
            {
                _params.gen_report = true;
                i += 1;
            }
            else
            {
                printf(
                    "%s has invalid number of parameters.\n",
                    INPUT_PARAM_OPTION_REPORT);
                _display_help(argv[0]);
                return 1;
            }
        }
        else if (strcmp(INPUT_PARAM_OPTION_OUT_FILE, argv[i]) == 0)
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
        else
        {
            printf("Invalid option: %s\n", argv[i]);
            return 1;
        }
    }

    if (_params.gen_cert && _params.gen_report)
    {
        printf("Please specify to generate a certificate or a report.\n");
        return 1;
    }

    return 0;
}

static oe_result_t _read_key(const char* filename, uint8_t** data, size_t* size)
{
    FILE* fp;
#ifdef _WIN32
    fopen_s(&fp, filename, "rb");
#else
    fp = fopen(filename, "rb");
#endif
    size_t file_size;
    oe_result_t result = OE_FAILURE;
    uint8_t* memory = NULL;

    if (fp == NULL)
        goto exit;

    // Find file size
    fseek(fp, 0, SEEK_END);
    file_size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Account for '\0'
    memory = (uint8_t*)malloc(file_size + 1);
    if (memory == NULL)
    {
        printf("Failed to allocate memory.\n");
        goto exit;
    }

    if (fread(memory, 1, file_size, fp) == file_size)
    {
        memory[file_size] = '\0';
        printf("Read in key: %s\n", memory);
    }
    else
    {
        printf("Failed to read in key: %s\n", filename);
        goto exit;
    }

    *data = memory;
    *size = file_size + 1;
    memory = NULL;

    result = OE_OK;

exit:
    if (fp)
        fclose(fp);
    if (memory)
        free(memory);

    return result;
}

static oe_result_t _process_params(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;

    if (_params.gen_cert)
    {
        size_t private_key_size;
        uint8_t* private_key;
        size_t public_key_size;
        uint8_t* public_key;

        // read private key (pem format)
        if (_read_key(
                _params.private_key_filename,
                &private_key,
                &private_key_size) == OE_OK &&
            _read_key(
                _params.public_key_filename, &public_key, &public_key_size) ==
                OE_OK)
        {
            result = _gen_cert(
                enclave,
                private_key,
                private_key_size,
                public_key,
                public_key_size,
                _params.out_filename);
        }
    }
    else if (_params.gen_report)
    {
        result = _gen_report(enclave, _params.out_filename);
    }

    return result;
}

#endif // OE_HAS_SGX_DCAP_QL

int main(int argc, const char* argv[])
{
    int ret = 0;

#ifdef OE_HAS_SGX_DCAP_QL
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("oecert not supported in simulation mode.\n");
        goto exit;
    }

    ret = _parse_args(argc, argv);
    if (ret != 0)
        goto exit;

    if ((result = oe_create_oecert_enclave(
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

    _process_params(enclave);

    result = oe_terminate_enclave(enclave);
exit:
#else
#pragma message( \
    "OE_HAS_SGX_DCAP_QL is not set to ON.  This tool requires DCAP libraries.")
    OE_UNUSED(argc);
    OE_UNUSED(argv);
#endif
    return ret;
}
