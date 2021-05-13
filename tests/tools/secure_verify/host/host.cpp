// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#include "secure_verify_u.h"

#include "evidence.h"

//#include "../../../../common/sgx/endorsements.h"

#define ENCLAVE_FILENAME_SUFFIX "_enc.signed"
#define DEFAULT_LOG_FILE "secure_verify.log"
#define INPUT_PARAM_OPTION_LOG_FILE "-l"
#define INPUT_PARAM_EVIDENCE_FILE "-i"
#define INPUT_PARAM_EVIDENCE_FORMAT "-f"
#define INPUT_PARAM_EVIDENCE_FORMAT_ECDSA "ecdsa"
#define INPUT_PARAM_EVIDENCE_FORMAT_REPORT "report"
#define INPUT_PARAM_EVIDENCE_FORMAT_QUOTE "quote"
#define INPUT_PARAM_EVIDENCE_FORMAT_CERT "cert"
#define INPUT_PARAM_OPTION_VERBOSE "--verbose"

#define OE_FORMAT_UUID_CERT                                               \
    {                                                                     \
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00                                  \
    }

static const oe_uuid_t _legacy_report_remote = {
    OE_FORMAT_UUID_LEGACY_REPORT_REMOTE};
static const oe_uuid_t raw_sgx_ecdsa_quote_uuid = {
    OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA};
static const oe_uuid_t _ecdsa_quote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _cert_uuid = {OE_FORMAT_UUID_CERT};

// Structure to store input parameters
//
typedef struct _input_params
{
    const char* evidence_filename;
    const oe_uuid_t* evidence_format;
    const char* log_filename;
    bool verbose;
} input_params_t;

static input_params_t _params;

FILE* log_file = nullptr;

static void _display_help(const char* cmd)
{
    printf(
        "\nUsage: %s <evidence_file> %s <evidence_format> [options]\n\n",
        cmd,
        INPUT_PARAM_EVIDENCE_FORMAT);
    printf(
        "evidence_format: {%s|%s|%s|%s}.\n",
        INPUT_PARAM_EVIDENCE_FORMAT_ECDSA,
        INPUT_PARAM_EVIDENCE_FORMAT_REPORT,
        INPUT_PARAM_EVIDENCE_FORMAT_QUOTE,
        INPUT_PARAM_EVIDENCE_FORMAT_CERT);
    printf("options:\n");
    printf(
        "\t%s <log filename> (default: %s)\n",
        INPUT_PARAM_OPTION_LOG_FILE,
        DEFAULT_LOG_FILE);
    printf("\t%s\n\n", INPUT_PARAM_OPTION_VERBOSE);
    printf("Example:\n");
    printf(
        "\t%s report.bin %s %s\n",
        cmd,
        INPUT_PARAM_EVIDENCE_FORMAT,
        INPUT_PARAM_EVIDENCE_FORMAT_REPORT);
}

// Get full path of secure_verify running executable, then get enclave filename
// by: In linux, replace "<path>/secure_verify" with
// "<path>/secure_verify_enc.signed" In windows, replace
// "<path>/secure_verify.exe" with "<path>/secure_verify_enc.signed"
static char* _get_enclave_filename()
{
    char* enclave_filename = nullptr;
    char path[OE_PATH_MAX];
    size_t path_size = 0;
    size_t enclave_filename_size = 0;

#if defined(__linux__)
    path_size += (size_t)readlink("/proc/self/exe", path, OE_PATH_MAX);
#elif defined(_WIN32)
    path_size += (size_t)GetModuleFileName(nullptr, path, OE_PATH_MAX);
    path_size -= strlen(".exe");
#endif

    if (path_size < 0 || path_size >= OE_PATH_MAX)
    {
        printf("Failed to read enclave full path.\n");
        goto done;
    }
    path[path_size] = '\0';
    enclave_filename_size = path_size + sizeof(ENCLAVE_FILENAME_SUFFIX);
    enclave_filename = (char*)malloc(enclave_filename_size);

    if (enclave_filename == nullptr)
    {
        printf("Failed to malloc enclave_filename.\n");
        goto done;
    }
    snprintf(
        enclave_filename,
        enclave_filename_size,
        "%s%s",
        path,
        ENCLAVE_FILENAME_SUFFIX);

    // Verify enclave file is valid
    FILE* fp;
    fopen_s(&fp, enclave_filename, "rb");
    if (!fp)
    {
        printf("Enclave file does not exist: %s.\n", enclave_filename);
        goto done;
    }
    else
        fclose(fp);

done:
    return enclave_filename;
}

static int _parse_args(int argc, const char* argv[])
{
    if (argc < 4)
    {
        return 1;
    }

    memset(&_params, 0, sizeof(_params));

    _params.evidence_filename = argv[1];
    _params.evidence_format = nullptr;
    _params.log_filename = DEFAULT_LOG_FILE;
    _params.verbose = false;

    int i = 2; // current index

    while (i < argc)
    {
        if (strcmp(INPUT_PARAM_EVIDENCE_FORMAT, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            const char* format = argv[i + 1];
            if (stricmp(format, INPUT_PARAM_EVIDENCE_FORMAT_ECDSA) == 0)
                _params.evidence_format = &_ecdsa_quote_uuid;
            else if (stricmp(format, INPUT_PARAM_EVIDENCE_FORMAT_REPORT) == 0)
                _params.evidence_format = &_legacy_report_remote;
            else if (stricmp(format, INPUT_PARAM_EVIDENCE_FORMAT_QUOTE) == 0)
                _params.evidence_format = &raw_sgx_ecdsa_quote_uuid;
            else if (stricmp(format, INPUT_PARAM_EVIDENCE_FORMAT_CERT) == 0)
                _params.evidence_format = &_cert_uuid;
            else
            {
                printf("Invalid format: %s\n", argv[i + 1]);
                return 1;
            }

            i += 2;
        }
        else if (strcmp(INPUT_PARAM_OPTION_LOG_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.log_filename = argv[i + 1];
            i += 2;
        }
        else if (strcmp(INPUT_PARAM_OPTION_VERBOSE, argv[i]) == 0)
        {
            _params.verbose = true;
            i++;
        }
        else
        {
            printf("Invalid option: %s\n\n", argv[i]);
            return 1;
        }
    }

    if (i < argc)
    {
        printf("%s has invalid number of parameters.\n\n", argv[i]);
        return 1;
    }

    if (_params.evidence_format == nullptr)
    {
        printf("Please specify format of the file to be verified.\n");
        return 1;
    }
    else if (_params.evidence_filename == nullptr)
    {
        printf("Please specify a file to be verified.\n");
        return 1;
    }

    return 0;
}

static oe_result_t _process_params(oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;

    if (_params.evidence_format == &_cert_uuid)
    {
        // TODO - verify certificate
        printf("Certificate format not supported.\n");
        result = OE_UNEXPECTED;
    }
    else
    {
        result = verify_oe_evidence(
            enclave, _params.evidence_format, _params.evidence_filename);
    }

done:
    return result;
}

int main(int argc, const char* argv[])
{
    int ret = 0;

    ret = _parse_args(argc, argv);
    if (ret != 0)
    {
        _display_help(argv[0]);
        return ret;
    }

    if (!oe_has_sgx_quote_provider())
    {
        fprintf(
            stderr, "FAILURE: DCAP libraries must be present for this test.\n");
        return -1;
    }

    oe_result_t result = OE_FAILURE;
    oe_enclave_t* enclave = nullptr;
    char* enclave_filename = nullptr;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("secure_verify not supported in simulation mode.\n");
        goto done;
    }

    enclave_filename = _get_enclave_filename();
    if (enclave_filename == nullptr)
    {
        printf("Fail to get enclave filename.\n");
        result = OE_UNSUPPORTED_ENCLAVE_IMAGE;
        goto done;
    }

    if ((result = oe_create_secure_verify_enclave(
             enclave_filename,
             OE_ENCLAVE_TYPE_AUTO,
             OE_ENCLAVE_FLAG_DEBUG,
             nullptr,
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
        result = OE_INVALID_PARAMETER;
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

    oe_terminate_enclave(enclave);
done:
    if (enclave_filename)
        free(enclave_filename);

    if (result == OE_OK)
        printf("\nEvidence verification succeeded.\n");
    else
        printf(
            "\nEvidence verification failed. Result = %s\n",
            oe_result_str(result));

    return ret;
}

#if 0 // TODO
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
    printf("identity->unique_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->unique_id[i]);

    printf("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);

    // verify signer id
    OE_CHECK_MSG(
        verify_signer_id(
            (char*)SECURE_VERIFY_ENC_PUBLIC_KEY,
            sizeof(SECURE_VERIFY_ENC_PUBLIC_KEY),
            identity->signer_id,
            sizeof(identity->signer_id)),
        "Failed to verify signer id. Error: (%s)\n",
        oe_result_str(result));

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
    const char* certificate_filename,
    bool verify,
    bool verbose)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t ecall_result;
    unsigned char* cert = nullptr;
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
        goto done;
    }
    if (certificate_filename)
    {
        result = output_file(certificate_filename, cert, cert_size);
        if (result != OE_OK)
        {
            printf(
                "Failed to open certificate file %s\n", certificate_filename);
            goto done;
        }
    }

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
                cert, cert_size, enclave_identity_verifier, nullptr),
            "Failed to verify certificate. result=%u (%s)\n",
            result,
            oe_result_str(result));

        log("========== Certificate verified\n\n");
    }

done:
    // deallcate resources
    if (cert)
        free(cert);

    fflush(stdout);
    return result;
}
#endif