// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
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
#include <time.h>
#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#include "secure_verify_u.h"

#include "evidence.h"

// #include "../../../../common/sgx/endorsements.h"

#define ENCLAVE_FILENAME_SUFFIX "_enc.signed"
#define DEFAULT_LOG_FILE "secure_verify.log"
#define INPUT_PARAM_OPTION_LOG_FILE "-l"
#define INPUT_PARAM_EVIDENCE_FILE "-i"
#define INPUT_PARAM_EVIDENCE_FORMAT "-f"
#define INPUT_PARAM_EVIDENCE_FORMAT_SGX_ECDSA "sgx_ecdsa"
#define INPUT_PARAM_EVIDENCE_FORMAT_SGX_REPORT "sgx_report"
#define INPUT_PARAM_EVIDENCE_FORMAT_SGX_QUOTE "sgx_quote"
#define INPUT_PARAM_EVIDENCE_FORMAT_SGX_CERT "sgx_cert"
#define INPUT_PARAM_EVIDENCE_FORMAT_TDX_QUOTE "tdx_quote"
#define INPUT_PARAM_OPTION_VERBOSE "--verbose"
#define INPUT_PARAM_OPTION_ENDORSEMENT_FILE "-e"

#define OE_FORMAT_UUID_CERT                                               \
    {                                                                     \
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00                                  \
    }

static const oe_uuid_t _legacy_sgx_report_remote = {
    OE_FORMAT_UUID_LEGACY_REPORT_REMOTE};
static const oe_uuid_t raw_sgx_ecdsa_quote_uuid = {
    OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA};
static const oe_uuid_t _sgx_ecdsa_quote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _sgx_cert_uuid = {OE_FORMAT_UUID_CERT};
static const oe_uuid_t _tdx_quote_uuid = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};

// Structure to store input parameters
//
typedef struct _input_params
{
    const char* enclave_filename;
    const char* evidence_filename;
    const char* endorsement_filename;
    const oe_uuid_t* evidence_format;
    const char* log_filename;
    bool verbose;
} input_params_t;

static input_params_t _params;

FILE* log_file = nullptr;

long get_tick()
{
    return clock() * 1000 / CLOCKS_PER_SEC;
}

static void _display_help(const char* cmd)
{
    printf(
        "\nUsage: %s <enclave_file> <evidence_file> %s <evidence_format> "
        "<endorsement_file> "
        "[options]\n\n",
        cmd,
        INPUT_PARAM_EVIDENCE_FORMAT);
    printf(
        "evidence_format: {%s|%s|%s|%s|%s}.\n",
        INPUT_PARAM_EVIDENCE_FORMAT_SGX_ECDSA,
        INPUT_PARAM_EVIDENCE_FORMAT_SGX_REPORT,
        INPUT_PARAM_EVIDENCE_FORMAT_SGX_QUOTE,
        INPUT_PARAM_EVIDENCE_FORMAT_SGX_CERT,
        INPUT_PARAM_EVIDENCE_FORMAT_TDX_QUOTE);
    printf("options:\n");
    printf(
        "\t%s <endorsement filename>\n", INPUT_PARAM_OPTION_ENDORSEMENT_FILE);
    printf(
        "\t%s <log filename> (default: %s)\n",
        INPUT_PARAM_OPTION_LOG_FILE,
        DEFAULT_LOG_FILE);
    printf("\t%s\n\n", INPUT_PARAM_OPTION_VERBOSE);
    printf("Example:\n");
    printf(
        "\t%s <enclave_file> report.bin %s %s\n",
        cmd,
        INPUT_PARAM_EVIDENCE_FORMAT,
        INPUT_PARAM_EVIDENCE_FORMAT_SGX_REPORT);
}

static int _parse_args(int argc, const char* argv[])
{
    if (argc < 4)
    {
        printf("Too few arguments (%d)\n", argc);
        return 1;
    }

    memset(&_params, 0, sizeof(_params));

    _params.enclave_filename = argv[1];
    _params.evidence_filename = argv[2];
    _params.evidence_format = nullptr;
    _params.log_filename = DEFAULT_LOG_FILE;
    _params.verbose = false;

    int i = 3; // current index

    while (i < argc)
    {
        if (strcmp(INPUT_PARAM_EVIDENCE_FORMAT, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            const char* format = argv[i + 1];
            if (strncmp(
                    format,
                    INPUT_PARAM_EVIDENCE_FORMAT_SGX_ECDSA,
                    strlen(INPUT_PARAM_EVIDENCE_FORMAT_SGX_ECDSA)) == 0)
                _params.evidence_format = &_sgx_ecdsa_quote_uuid;
            else if (
                strncmp(
                    format,
                    INPUT_PARAM_EVIDENCE_FORMAT_SGX_REPORT,
                    strlen(INPUT_PARAM_EVIDENCE_FORMAT_SGX_REPORT)) == 0)
                _params.evidence_format = &_legacy_sgx_report_remote;
            else if (
                strncmp(
                    format,
                    INPUT_PARAM_EVIDENCE_FORMAT_SGX_QUOTE,
                    strlen(INPUT_PARAM_EVIDENCE_FORMAT_SGX_QUOTE)) == 0)
                _params.evidence_format = &raw_sgx_ecdsa_quote_uuid;
            else if (
                strncmp(
                    format,
                    INPUT_PARAM_EVIDENCE_FORMAT_SGX_CERT,
                    strlen(INPUT_PARAM_EVIDENCE_FORMAT_SGX_CERT)) == 0)
                _params.evidence_format = &_sgx_cert_uuid;
            else if (
                strncmp(
                    format,
                    INPUT_PARAM_EVIDENCE_FORMAT_TDX_QUOTE,
                    strlen(INPUT_PARAM_EVIDENCE_FORMAT_TDX_QUOTE)) == 0)
                _params.evidence_format = &_tdx_quote_uuid;
            else
            {
                printf("Invalid format: %s\n", argv[i + 1]);
                return 1;
            }

            i += 2;
        }
        else if (strcmp(INPUT_PARAM_OPTION_ENDORSEMENT_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;
            _params.endorsement_filename = argv[i + 1];
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

    return 0;
}

static oe_result_t _verify_evidence(oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;

    if (_params.evidence_format == &_sgx_cert_uuid)
    {
        // TODO - verify certificate
        printf("Certificate format not supported.\n");
        result = OE_UNEXPECTED;
    }
    else
    {
        result = verify_oe_evidence(
            enclave,
            _params.evidence_format,
            _params.evidence_filename,
            _params.endorsement_filename);
    }

    return result;
}

int main(int argc, const char* argv[])
{
    int ret = 0;
    long tick1 = 0, tick2 = 0;

    ret = _parse_args(argc, argv);
    if (ret != 0)
    {
        _display_help(argv[0]);
        return ret;
    }

    if (!oe_sgx_has_quote_provider())
    {
        fprintf(
            stderr, "FAILURE: DCAP libraries must be present for this test.\n");
        return -1;
    }

    oe_result_t result = OE_FAILURE;
    oe_enclave_t* enclave = nullptr;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("secure_verify not supported in simulation mode.\n");
        result = OE_OK;
        goto done;
    }

    if (_params.enclave_filename == nullptr)
    {
        printf("Fail to get enclave filename.\n");
        result = OE_UNSUPPORTED_ENCLAVE_IMAGE;
        goto done;
    }

    if ((result = oe_create_secure_verify_enclave(
             _params.enclave_filename,
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

    tick1 = get_tick();
    result = _verify_evidence(enclave);
    tick2 = get_tick();

    if (result != OE_OK)
    {
        printf(
            "Failed to process parameters. Error: %s\n", oe_result_str(result));
        ret = 1;
        goto done;
    }

    oe_terminate_enclave(enclave);
done:
    if (result == OE_OK)
        printf(
            "\nEvidence verification succeeded in %ld msec.\n",
            (tick2 - tick1));
    else
    {
        printf(
            "\nEvidence verification failed. Result = %s\n",
            oe_result_str(result));
        ret = 1;
    }

    return ret;
}
