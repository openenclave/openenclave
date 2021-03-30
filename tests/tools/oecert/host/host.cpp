// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oecert_u.h"

#include "evidence.h"

#include "../../../../common/sgx/endorsements.h"

#define INPUT_PARAM_OPTION_CERT "--cert"
#define INPUT_PARAM_OPTION_REPORT "--report"
#define INPUT_PARAM_OPTION_EVIDENCE "--evidence"
#define INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME "--endorsements"
#define INPUT_PARAM_OPTION_VERIFY "--verify"
#define DEFAULT_OUT_FILE "out.bin"
#define INPUT_PARAM_OPTION_OUT_FILE "--out"
#define DEFAULT_LOG_FILE "oecert.log"
#define INPUT_PARAM_OPTION_LOG_FILE "--log"
#define INPUT_PARAM_OPTION_VERBOSE "--verbose"

// Structure to store input parameters
//
typedef struct _input_params
{
    const char* enclave_filename;
    const char* private_key_filename;
    const char* public_key_filename;
    const char* out_filename;
    const char* log_filename;
    const char* endorsements_filename;
    bool generate_certificate;
    bool generate_report;
    bool generate_evidence;
    bool verify;
    bool verbose;
} input_params_t;

static input_params_t _params;

FILE* log_file = nullptr;

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

static oe_result_t generate_certificate(
    oe_enclave_t* enclave,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    const char* out_filename,
    bool verify,
    bool verbose)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t ecall_result;
    unsigned char* cert = NULL;
    size_t cert_size = 0;
    uint8_t* report = nullptr;
    size_t report_size = 0;

    log("========== Creating certificate with given private/public keys.\n");
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
        goto done;
    }
    output_file(out_filename, cert, cert_size);

    if (verbose)
    {
        printf("\n");
        dump_certificate(cert, cert_size);

        if (get_oe_report_from_certificate(
                cert, cert_size, &report, &report_size) == OE_OK)
        {
            dump_oe_report(report, report_size);
        }
    }

    log("========== Got cert = %p cert_size = %zu\n", cert, cert_size);

    if (verify) // validate cert
    {
        OE_CHECK_MSG(
            oe_verify_attestation_certificate(
                cert, cert_size, enclave_identity_verifier, NULL),
            "Failed to verify certificate. result=%u (%s)\n",
            result,
            oe_result_str(result));

        log("========== Certificate verified\n\n");
    }
    fflush(stdout);

done:
    // deallcate resources
    if (cert)
        free(cert);

    return result;
}

static void _display_help(const char* cmd)
{
    printf("Usage: %s ENCLAVE_PATH Options\n", cmd);
    printf("\tOptions:\n");
    printf(
        "\t%s <privkey> <pubkey> : generate der remote attestation "
        "certificate.\n",
        INPUT_PARAM_OPTION_CERT);
    printf(
        "\t%s : generate binary enclave report\n", INPUT_PARAM_OPTION_REPORT);
    printf(
        "\t%s : generate binary enclave evidence.\n",
        INPUT_PARAM_OPTION_EVIDENCE);
    printf(
        "\t%s <output filename> : file for certificate, report or evidence "
        "(default: %s)\n",
        INPUT_PARAM_OPTION_OUT_FILE,
        DEFAULT_OUT_FILE);
    printf(
        "\t%s : file for endorsements (use with %s or %s).\n",
        INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME,
        INPUT_PARAM_OPTION_REPORT,
        INPUT_PARAM_OPTION_EVIDENCE);
    printf(
        "\t%s : verify the generated certificate, report or evidence\n",
        INPUT_PARAM_OPTION_VERIFY);
    printf(
        "\t%s <log filename> (default: %s)\n",
        INPUT_PARAM_OPTION_LOG_FILE,
        DEFAULT_LOG_FILE);
    printf("\t%s\n", INPUT_PARAM_OPTION_VERBOSE);
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
    _params.generate_report = false;
    _params.generate_certificate = false;
    _params.generate_evidence = false;

    int i = 1; // current index
    // save
    _params.enclave_filename = argv[i++];
    _params.out_filename = DEFAULT_OUT_FILE;
    _params.endorsements_filename = NULL;
    _params.log_filename = DEFAULT_LOG_FILE;
    _params.verify = false;
    _params.verbose = false;

    // Verify enclave file is valid
    FILE* fp;
    fopen_s(&fp, _params.enclave_filename, "rb");
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
                _params.generate_certificate = true;
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
                _params.generate_report = true;
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
        else if (strcmp(INPUT_PARAM_OPTION_EVIDENCE, argv[i]) == 0)
        {
            if (argc >= i)
            {
                _params.generate_evidence = true;
                i += 1;
            }
            else
            {
                printf(
                    "%s has invalid number of parameters.\n",
                    INPUT_PARAM_OPTION_EVIDENCE);
                _display_help(argv[0]);
                return 1;
            }
        }
        else if (strcmp(INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME, argv[i]) == 0)
        {
            if (argc >= i + 1)
            {
                _params.endorsements_filename = argv[i + 1];
                i += 2;
            }
            else
            {
                printf(
                    "%s has invalid number of parameters.\n",
                    INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME);
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

        else if (strcmp(INPUT_PARAM_OPTION_VERIFY, argv[i]) == 0)
        {
            _params.verify = true;
            i++;
        }

        else if (strcmp(INPUT_PARAM_OPTION_LOG_FILE, argv[i]) == 0)
        {
            if (argc >= i + 1)
            {
                _params.log_filename = argv[i + 1];
                i += 2;
            }
            else
            {
                printf(
                    "%s has invalid number of parameters.\n",
                    INPUT_PARAM_OPTION_LOG_FILE);
                _display_help(argv[0]);
                return 1;
            }
        }

        else if (strcmp(INPUT_PARAM_OPTION_VERBOSE, argv[i]) == 0)
        {
            _params.verbose = true;
            i++;
        }

        else
        {
            printf("Invalid option: %s\n", argv[i]);
            return 1;
        }
    }

    if (_params.generate_certificate && _params.generate_report &&
        _params.generate_evidence)
    {
        printf("Please specify to generate a certificate, a report, or "
               "evidence.\n");
        return 1;
    }

    return 0;
}

static oe_result_t _read_key(const char* filename, uint8_t** data, size_t* size)
{
    FILE* fp;
    fopen_s(&fp, filename, "rb");
    size_t file_size;
    oe_result_t result = OE_FAILURE;
    uint8_t* memory = NULL;

    if (fp == NULL)
        goto done;

    // Find file size
    fseek(fp, 0, SEEK_END);
    file_size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Account for '\0'
    memory = (uint8_t*)malloc(file_size + 1);
    if (memory == NULL)
    {
        printf("Failed to allocate memory.\n");
        goto done;
    }

    if (fread(memory, 1, file_size, fp) == file_size)
    {
        memory[file_size] = '\0';
        printf("Read in key: %s\n", memory);
    }
    else
    {
        printf("Failed to read in key: %s\n", filename);
        goto done;
    }

    *data = memory;
    *size = file_size + 1;
    memory = NULL;

    result = OE_OK;

done:
    if (fp)
        fclose(fp);
    if (memory)
        free(memory);

    return result;
}

static oe_result_t _process_params(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;

    if (_params.generate_certificate)
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
            result = generate_certificate(
                enclave,
                private_key,
                private_key_size,
                public_key,
                public_key_size,
                _params.out_filename,
                _params.verify,
                _params.verbose);
        }
    }
    else if (_params.generate_report)
    {
        result = generate_oe_report(
            enclave,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose);
    }
    else if (_params.generate_evidence)
    {
        result = generate_oe_evidence(
            enclave,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose);
    }

    return result;
}

int main(int argc, const char* argv[])
{
    int ret = 0;

    if (!oe_has_sgx_quote_provider())
    {
        fprintf(
            stderr, "FAILURE: DCAP libraries must be present for this test.\n");
        return -1;
    }

    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("oecert not supported in simulation mode.\n");
        goto done;
    }

    ret = _parse_args(argc, argv);
    if (ret != 0)
        goto done;

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
        goto done;
    }

    // Create log file
#ifdef _WIN32
    fopen_s(&log_file, _params.log_filename, "w");
#else
    log_file = fopen(_params.log_filename, "w");
#endif
    if (!log_file)
    {
        printf("Failed to open log file %s\n", _params.log_filename);
        ret = 1;
        goto done;
    }

    set_log_callback();

    if ((result = _process_params(enclave)) != OE_OK)
    {
        printf(
            "Failed to process parameters. Error: %s\n", oe_result_str(result));
        ret = 1;
        goto done;
    }

    result = oe_terminate_enclave(enclave);
done:

    return ret;
}
