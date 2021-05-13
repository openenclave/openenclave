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
#define strcasecmp stricmp
#endif
#include "oegenerate_u.h"

#include "evidence.h"

#include "../../../common/sgx/endorsements.h"

#define DEFAULT_LOG_FILE "oegenerate.log"
#define ENCLAVE_FILENAME_SUFFIX "_enc.signed"
#define INPUT_PARAM_OPTION_FORMAT "--format"
#define INPUT_PARAM_OPTION_CERT "cert"
#define INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME "--endorsements"
#define INPUT_PARAM_OPTION_QUOTE_PROC "--quote-proc"
#define INPUT_PARAM_QUOTE_IN_PROC "in"
#define INPUT_PARAM_QUOTE_OUT_OF_PROC "out"
#define INPUT_PARAM_OPTION_VERIFY "--verify"
#define INPUT_PARAM_OPTION_OUT_FILE "--out"
#define INPUT_PARAM_OPTION_LOG_FILE "--log"
#define INPUT_PARAM_OPTION_VERBOSE "--verbose"
#define INPUT_PARAM_OPTION_LEGACY_REPORT_REMOTE "LEGACY_REPORT_REMOTE"
#define INPUT_PARAM_OPTION_SGX_ECDSA "SGX_ECDSA"
#define INPUT_PARAM_OPTION_SGX_EPID_LINKABLE "SGX_EPID_LINKABLE"
#define INPUT_PARAM_OPTION_SGX_EPID_UNLINKABLE "SGX_EPID_UNLINKABLE"
#define SHORT_INPUT_PARAM_OPTION_FORMAT "-f"
#define SHORT_INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME "-e"
#define SHORT_INPUT_PARAM_OPTION_QUOTE_PROC "-p"
#define SHORT_INPUT_PARAM_OPTION_VERIFY "-v"
#define SHORT_INPUT_PARAM_OPTION_OUT_FILE "-o"
#define SHORT_INPUT_PARAM_OPTION_LOG_FILE "-l"
#define SGX_AESM_ADDR "SGX_AESM_ADDR"
#if defined(_WIN32)
#define SGX_AESM_ADDR_MAXSIZE 32
#endif

// Static constants for evidence UUIDs
static const oe_uuid_t _sgx_ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _sgx_epid_linkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_LINKABLE};
static const oe_uuid_t _sgx_epid_unlinkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_UNLINKABLE};

// Structure to store input parameters
typedef struct _input_params
{
    const char* private_key_filename;
    const char* public_key_filename;
    const char* out_filename;
    const char* log_filename;
    const char* endorsements_filename;
    const char* quote_proc;
    bool generate_certificate;
    bool generate_legacy_report_remote;
    bool generate_sgx_ecdsa;
    bool generate_sgx_epid_linkable;
    bool generate_sgx_epid_unlinkable;
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
    printf("identity->unique_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->unique_id[i]);

    printf("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);

    // verify signer id
    OE_CHECK_MSG(
        verify_signer_id(
            (char*)OEGENERATE_ENC_PUBLIC_KEY,
            sizeof(OEGENERATE_ENC_PUBLIC_KEY),
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

static void _display_help(const char* cmd)
{
    printf("Usage:\t%s <Options>\n", cmd);
    printf("Options:\n");
    printf(
        "\t%s, %s <format_option>: generate evidence, a report, or a "
        "certificate, where format_option can be one of the following (case "
        "insensitive):\n",
        SHORT_INPUT_PARAM_OPTION_FORMAT,
        INPUT_PARAM_OPTION_FORMAT);
    printf(
        "\t\t%s <private_key> <public_key>: a remote attestation certificate "
        "in DER format.\n",
        INPUT_PARAM_OPTION_CERT);
    printf(
        "\t\t%s: a report in OE_FORMAT_UUID_LEGACY_REPORT_REMOTE format.\n",
        INPUT_PARAM_OPTION_LEGACY_REPORT_REMOTE);
    printf(
        "\t\t%s: evidence in OE_FORMAT_UUID_SGX_ECDSA format.\n",
        INPUT_PARAM_OPTION_SGX_ECDSA);
    printf(
        "\t\t%s: evidence in OE_FORMAT_UUID_SGX_EPID_LINKABLE format.\n",
        INPUT_PARAM_OPTION_SGX_EPID_LINKABLE);
    printf(
        "\t\t%s: evidence in OE_FORMAT_UUID_SGX_EPID_UNLINKABLE format.\n",
        INPUT_PARAM_OPTION_SGX_EPID_UNLINKABLE);
    printf(
        "\t%s, %s <in|out>: use SGX in-process or out-of-process quoting.\n",
        SHORT_INPUT_PARAM_OPTION_QUOTE_PROC,
        INPUT_PARAM_OPTION_QUOTE_PROC);
    printf(
        "\t%s, %s <filename>: generate an output file for a remote attestation "
        "certificate, a report, or evidence.\n",
        SHORT_INPUT_PARAM_OPTION_OUT_FILE,
        INPUT_PARAM_OPTION_OUT_FILE);
    printf(
        "\t%s, %s <filename>: output a report in LEGACY_REPORT_REMOTE format "
        "or evidence, and also its "
        "endorsements binary.\n",
        SHORT_INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME,
        INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME);
    printf(
        "\t%s, %s: verify the generated remote attestation certificate, "
        "report, "
        "or evidence.\n",
        SHORT_INPUT_PARAM_OPTION_VERIFY,
        INPUT_PARAM_OPTION_VERIFY);
    printf(
        "\t%s, %s <filename>: generate a log file (default: %s).\n",
        SHORT_INPUT_PARAM_OPTION_LOG_FILE,
        INPUT_PARAM_OPTION_LOG_FILE,
        DEFAULT_LOG_FILE);
    printf("\t%s: enable verbose output.\n", INPUT_PARAM_OPTION_VERBOSE);
    printf("Examples:\n");
    printf("\t1. Show the verification results of evidence in SGX_ECDSA "
           "format:\n");
    printf("\t\toegenerate -f sgx_ecdsa -v\n");
    printf("\t2. Generate a certificate:\n");
    printf("\t\toegenerate -f cert private.pem public.pem -o mycert.der\n");
    printf("\t3. Generate a report:\n");
    printf("\t\toegenerate --format legacy_report_remote --out report.bin\n");
}

// Get full path of oegenerate running executable, then get enclave filename by:
// In linux, replace "<path>/oegenerate" with "<path>/oegenerate_enc.signed"
// In windows, replace "<path>/oegenerate.exe" with
// "<path>/oegenerate_enc.signed"
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
    if (argc < 3)
    {
        _display_help(argv[0]);
        return 1;
    }

    // clear params memory
    memset(&_params, 0, sizeof(_params));

    // save
    _params.generate_certificate = false;
    _params.generate_legacy_report_remote = false;
    _params.generate_sgx_ecdsa = false;
    _params.generate_sgx_epid_linkable = false;
    _params.generate_sgx_epid_unlinkable = false;
    _params.out_filename = nullptr;
    _params.endorsements_filename = nullptr;
    _params.log_filename = DEFAULT_LOG_FILE;
    _params.quote_proc = "";
    _params.verify = false;
    _params.verbose = false;

    int i = 1; // current index

    while (i < argc)
    {
        if (strcasecmp(INPUT_PARAM_OPTION_FORMAT, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_FORMAT, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            if (strcasecmp(INPUT_PARAM_OPTION_CERT, argv[i + 1]) == 0)
            {
                if (argc < i + 4)
                    break;

                _params.generate_certificate = true;
                _params.private_key_filename = argv[i + 2];
                _params.public_key_filename = argv[i + 3];
                i += 4;
            }
            else if (
                strcasecmp(
                    INPUT_PARAM_OPTION_LEGACY_REPORT_REMOTE, argv[i + 1]) == 0)
            {
                _params.generate_legacy_report_remote = true;
                i += 2;
            }
            else if (strcasecmp(INPUT_PARAM_OPTION_SGX_ECDSA, argv[i + 1]) == 0)
            {
                _params.generate_sgx_ecdsa = true;
                i += 2;
            }
            else if (
                strcasecmp(INPUT_PARAM_OPTION_SGX_EPID_LINKABLE, argv[i + 1]) ==
                0)
            {
                _params.generate_sgx_epid_linkable = true;
                i += 2;
            }
            else if (
                strcasecmp(
                    INPUT_PARAM_OPTION_SGX_EPID_UNLINKABLE, argv[i + 1]) == 0)
            {
                _params.generate_sgx_epid_unlinkable = true;
                i += 2;
            }
            else
            {
                printf("Invalid format: %s\n\n", argv[i + 1]);
                break;
            }
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_QUOTE_PROC, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_QUOTE_PROC, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.quote_proc = argv[i + 1];
            if (strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) !=
                    0 &&
                strcasecmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) !=
                    0)
            {
                printf(
                    "Please use 'in' or 'out' with %s.\n",
                    INPUT_PARAM_OPTION_QUOTE_PROC);
                return 1;
            }
            i += 2;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME, argv[i]) ==
                0 ||
            strcasecmp(
                SHORT_INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.endorsements_filename = argv[i + 1];
            i += 2;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_OUT_FILE, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_OUT_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.out_filename = argv[i + 1];
            i += 2;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_VERIFY, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_VERIFY, argv[i]) == 0)
        {
            _params.verify = true;
            i++;
        }
        else if (
            strcasecmp(INPUT_PARAM_OPTION_LOG_FILE, argv[i]) == 0 ||
            strcasecmp(SHORT_INPUT_PARAM_OPTION_LOG_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.log_filename = argv[i + 1];
            i += 2;
        }
        else if (strcasecmp(INPUT_PARAM_OPTION_VERBOSE, argv[i]) == 0)
        {
            _params.verbose = true;
            i++;
        }
        else
        {
            printf("Invalid option: %s\n\n", argv[i]);
            _display_help(argv[0]);
            return 1;
        }
    }

    if (i < argc)
    {
        printf("%s has invalid number of parameters.\n\n", argv[i]);
        _display_help(argv[0]);
        return 1;
    }

    if (_params.generate_certificate + _params.generate_legacy_report_remote +
            _params.generate_sgx_ecdsa + _params.generate_sgx_epid_linkable +
            _params.generate_sgx_epid_unlinkable !=
        1)
    {
        printf("Please specify to generate a certificate, a report, or "
               "evidence in SGX_ECDSA, SGX_EPID_LINKABLE or "
               "SGX_EPID_UNLINKABLE format.\n");
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
    uint8_t* memory = nullptr;

    if (fp == nullptr)
        goto done;

    // Find file size
    fseek(fp, 0, SEEK_END);
    file_size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Account for '\0'
    memory = (uint8_t*)malloc(file_size + 1);
    if (memory == nullptr)
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
    memory = nullptr;

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

#if defined(__linux__)
    char* sgx_aesm_env = getenv(SGX_AESM_ADDR);

    // For Linux, if "SGX_AESM_ADDR" not set and out-of-proc is required, set
    // "SGX_AESM_ADDR" to "1" and unset after process finishes
    if (sgx_aesm_env == nullptr)
    {
        if (strcasecmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) ==
                0 &&
            setenv(SGX_AESM_ADDR, "1", 1) != 0)
        {
            printf("Failed to set environment variable 'SGX_AESM_ADDR'\n");
            goto done;
        }
    }
    // if "SGX_AESM_ADDR" is set and in-proc is required, unset it during the
    // process and reset it to its original value after process finishes
    else if (
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0 &&
        unsetenv(SGX_AESM_ADDR) != 0)
    {
        printf("Failed to unset environment variable 'SGX_AESM_ADDR'\n");
        goto done;
    }
#elif defined(_WIN32)
    char sgx_aesm_env[SGX_AESM_ADDR_MAXSIZE];
    int env_size = GetEnvironmentVariableA(
        SGX_AESM_ADDR, sgx_aesm_env, SGX_AESM_ADDR_MAXSIZE);

    if ((env_size == 0 && GetLastError() != ERROR_ENVVAR_NOT_FOUND) ||
        env_size >= SGX_AESM_ADDR_MAXSIZE)
    {
        printf("Fail to read environment variable 'SGX_AESM_ADDR'\n");
        goto done;
    }

    // For Windows, out-of-proc is not tested as extra dependencies required
    if (strcasecmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) == 0)
    {
        printf("In-proc quoting is by default on Windows. Please use in-proc "
               "quoting\n");
        goto done;
    }
    // if "SGX_AESM_ADDR" is set and in-proc is required, unset it during the
    // process and reset it to its original value after process finishes
    else if (
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0 &&
        env_size != 0 && SetEnvironmentVariableA(SGX_AESM_ADDR, nullptr) == 0)
    {
        printf("Failed to unset environment variable 'SGX_AESM_ADDR'\n");
        goto done;
    }
#endif

    if (_params.generate_certificate)
    {
        size_t private_key_size;
        uint8_t* private_key;
        size_t public_key_size;
        uint8_t* public_key;

        // read private key (pem format)
        OE_CHECK(_read_key(
            _params.private_key_filename, &private_key, &private_key_size));
        OE_CHECK(_read_key(
            _params.public_key_filename, &public_key, &public_key_size));
        OE_CHECK(generate_certificate(
            enclave,
            private_key,
            private_key_size,
            public_key,
            public_key_size,
            _params.out_filename,
            _params.verify,
            _params.verbose));
    }
    else if (_params.generate_legacy_report_remote)
    {
        OE_CHECK(generate_oe_report(
            enclave,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose));
    }
    else if (_params.generate_sgx_ecdsa)
    {
        OE_CHECK(generate_oe_evidence(
            enclave,
            _sgx_ecdsa_uuid,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose));
    }
    else if (_params.generate_sgx_epid_linkable)
    {
        OE_CHECK(generate_oe_evidence(
            enclave,
            _sgx_epid_linkable_uuid,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose));
    }
    else if (_params.generate_sgx_epid_unlinkable)
    {
        OE_CHECK(generate_oe_evidence(
            enclave,
            _sgx_epid_unlinkable_uuid,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose));
    }

    result = OE_OK;

done:

#if defined(__linux__)
    if (sgx_aesm_env == nullptr)
    {
        if (strcasecmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) ==
                0 &&
            unsetenv(SGX_AESM_ADDR) != 0)
        {
            printf(
                "Failed to unset environment variable 'SGX_AESM_ADDR', please "
                "manually unset it\n");
            result = OE_FAILURE;
        }
    }
    else if (
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0 &&
        setenv(SGX_AESM_ADDR, sgx_aesm_env, 1) != 0)
    {
        printf(
            "Failed to reset environment variable 'SGX_AESM_ADDR', please "
            "manually reset it as %s\n",
            sgx_aesm_env);
        result = OE_FAILURE;
    }
#elif defined(_WIN32)
    if (env_size != 0 &&
        strcasecmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0)
    {
        if (SetEnvironmentVariableA(SGX_AESM_ADDR, sgx_aesm_env) == 0)
        {
            printf(
                "Failed to reset environment variable 'SGX_AESM_ADDR', please "
                "manually reset it as %s\n",
                sgx_aesm_env);
            result = OE_FAILURE;
        }
    }
#endif
    return result;
}

int main(int argc, const char* argv[])
{
    int ret = 0;
    printf(
        "NOTICE: oegenerate is purely a debugging utility and not suitable for "
        "production use.\n\n");
    if (!oe_has_sgx_quote_provider())
    {
        fprintf(
            stderr, "FAILURE: DCAP libraries must be present for this test.\n");
        return -1;
    }

    oe_result_t result;
    oe_enclave_t* enclave = nullptr;
    char* enclave_filename = nullptr;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("oegenerate not supported in simulation mode.\n");
        goto done;
    }

    enclave_filename = _get_enclave_filename();
    if (enclave_filename == nullptr)
    {
        printf("Fail to get enclave filename.\n");
        goto done;
    }

    ret = _parse_args(argc, argv);
    if (ret != 0)
        goto done;

    if ((result = oe_create_oegenerate_enclave(
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

    if (enclave_filename)
        free(enclave_filename);
    return ret;
}
