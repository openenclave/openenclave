// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

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
#include "oecert_u.h"

#include "evidence.h"

#include "../../../../common/sgx/endorsements.h"

#define ENCLAVE_FILENAME_SUFFIX "_enc.signed"
#define INPUT_PARAM_OPTION_CERT "--cert"
#define INPUT_PARAM_OPTION_REPORT "--report"
#define INPUT_PARAM_OPTION_EVIDENCE "--evidence"
#define INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME "--endorsements"
#define INPUT_PARAM_OPTION_QUOTE_PROC "--quote-proc"
#define INPUT_PARAM_QUOTE_IN_PROC "in"
#define INPUT_PARAM_QUOTE_OUT_OF_PROC "out"
#define INPUT_PARAM_OPTION_VERIFY "--verify"
#define INPUT_PARAM_OPTION_OUT_FILE "--out"
#define DEFAULT_LOG_FILE "oecert.log"
#define INPUT_PARAM_OPTION_LOG_FILE "--log"
#define INPUT_PARAM_OPTION_VERBOSE "--verbose"
#define SGX_AESM_ADDR "SGX_AESM_ADDR"
#if defined(_WIN32)
#define SGX_AESM_ADDR_MAXSIZE 32
#endif

// Structure to store input parameters
//
typedef struct _input_params
{
    const char* private_key_filename;
    const char* public_key_filename;
    const char* out_filename;
    const char* log_filename;
    const char* endorsements_filename;
    const char* quote_proc;
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
    printf("Usage: %s <Options>\n", cmd);
    printf("Options:\n");
    printf(
        "\t%s <privkey> <pubkey> : generate der remote attestation "
        "certificate.\n",
        INPUT_PARAM_OPTION_CERT);
    printf(
        "\t%s <in|out>: use sgx in process or out-of-process quoting.\n",
        INPUT_PARAM_OPTION_QUOTE_PROC);
    printf(
        "\t%s <output filename> : file for %s, %s, or %s.\n",
        INPUT_PARAM_OPTION_OUT_FILE,
        INPUT_PARAM_OPTION_CERT,
        INPUT_PARAM_OPTION_REPORT,
        INPUT_PARAM_OPTION_EVIDENCE);
    printf(
        "\t%s : file for endorsements (use with %s or %s).\n",
        INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME,
        INPUT_PARAM_OPTION_REPORT,
        INPUT_PARAM_OPTION_EVIDENCE);
    printf(
        "\t%s : verify the generated %s, %s, or %s\n",
        INPUT_PARAM_OPTION_VERIFY,
        INPUT_PARAM_OPTION_CERT,
        INPUT_PARAM_OPTION_REPORT,
        INPUT_PARAM_OPTION_EVIDENCE);
    printf(
        "\t%s <log filename> (default: %s)\n",
        INPUT_PARAM_OPTION_LOG_FILE,
        DEFAULT_LOG_FILE);
    printf("\t%s\n", INPUT_PARAM_OPTION_VERBOSE);
}

// Get full path of oecert running executable, then get enclave filename by:
// In linux, replace "<path>/oecert" with "<path>/oecert_enc.signed"
// In windows, replace "<path>/oecert.exe" with "<path>/oecert_enc.signed"
static char* _get_enclave_filename()
{
    char* enclave_filename = nullptr;
    char path[OE_PATH_MAX];
    size_t path_size = 0;

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

    enclave_filename =
        (char*)malloc(path_size + sizeof(ENCLAVE_FILENAME_SUFFIX));

    if (enclave_filename == nullptr)
    {
        printf("Failed to malloc enclave_filename.\n");
        goto done;
    }

    strcpy(enclave_filename, path);
    strcat(enclave_filename, ENCLAVE_FILENAME_SUFFIX);

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
    if (argc < 2)
    {
        _display_help(argv[0]);
        return 1;
    }

    // clear params memory
    memset(&_params, 0, sizeof(_params));

    // save
    _params.generate_report = false;
    _params.generate_certificate = false;
    _params.generate_evidence = false;
    _params.out_filename = nullptr;
    _params.endorsements_filename = nullptr;
    _params.log_filename = DEFAULT_LOG_FILE;
    _params.quote_proc = "";
    _params.verify = false;
    _params.verbose = false;

    int i = 1; // current index

    while (i < argc)
    {
        if (strcmp(INPUT_PARAM_OPTION_CERT, argv[i]) == 0)
        {
            if (argc < i + 3)
                break;

            _params.generate_certificate = true;
            _params.private_key_filename = argv[i + 1];
            _params.public_key_filename = argv[i + 2];
            i += 3;
        }
        else if (strcmp(INPUT_PARAM_OPTION_REPORT, argv[i]) == 0)
        {
            _params.generate_report = true;
            i++;
        }
        else if (strcmp(INPUT_PARAM_OPTION_EVIDENCE, argv[i]) == 0)
        {
            _params.generate_evidence = true;
            i++;
        }
        else if (strcmp(INPUT_PARAM_OPTION_QUOTE_PROC, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.quote_proc = argv[i + 1];
            if (strcmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) != 0 &&
                strcmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) != 0)
            {
                printf(
                    "Please use 'in' or 'out' with %s.\n",
                    INPUT_PARAM_OPTION_QUOTE_PROC);
                return 1;
            }
            i += 2;
        }
        else if (strcmp(INPUT_PARAM_OPTION_ENDORSEMENTS_FILENAME, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.endorsements_filename = argv[i + 1];
            i += 2;
        }

        else if (strcmp(INPUT_PARAM_OPTION_OUT_FILE, argv[i]) == 0)
        {
            if (argc < i + 2)
                break;

            _params.out_filename = argv[i + 1];
            i += 2;
        }

        else if (strcmp(INPUT_PARAM_OPTION_VERIFY, argv[i]) == 0)
        {
            _params.verify = true;
            i++;
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
    char* sgx_asem_env = getenv(SGX_AESM_ADDR);

    // For Linux, if "SGX_AESM_ADDR" not set and out-of-proc is required, set
    // "SGX_AESM_ADDR" to "1" and unset after process finishes
    if (sgx_asem_env == nullptr)
    {
        if (strcmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) == 0 &&
            setenv(SGX_AESM_ADDR, "1", 1) != 0)
        {
            printf("Failed to set environment variable 'SGX_AESM_ADDR'\n");
            goto done;
        }
    }
    // if "SGX_AESM_ADDR" is set and in-proc is required, unset it during the
    // process and reset it to its original value after process finishes
    else if (
        strcmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0 &&
        unsetenv(SGX_AESM_ADDR) != 0)
    {
        printf("Failed to unset environment variable 'SGX_AESM_ADDR'\n");
        goto done;
    }
#elif defined(_WIN32)
    char sgx_asem_env[SGX_AESM_ADDR_MAXSIZE];
    int env_size = GetEnvironmentVariableA(
        SGX_AESM_ADDR, sgx_asem_env, SGX_AESM_ADDR_MAXSIZE);

    if ((env_size == 0 && GetLastError() != ERROR_ENVVAR_NOT_FOUND) ||
        env_size >= SGX_AESM_ADDR_MAXSIZE)
    {
        printf(
            "Fail to read environment variable 'SGX_AESM_ADDR'\n",
            INPUT_PARAM_OPTION_QUOTE_PROC);
        goto done;
    }

    // For Windows, out-of-proc is not tested as extra dependencies required
    if (strcmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) == 0)
    {
        printf("In-proc quoting is by default on Windows. Please use in-proc "
               "quoting\n");
        goto done;
    }
    // if "SGX_AESM_ADDR" is set and in-proc is required, unset it during the
    // process and reset it to its original value after process finishes
    else if (
        strcmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0 &&
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
    else if (_params.generate_report)
    {
        OE_CHECK(generate_oe_report(
            enclave,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose));
    }
    else if (_params.generate_evidence)
    {
        OE_CHECK(generate_oe_evidence(
            enclave,
            _params.out_filename,
            _params.endorsements_filename,
            _params.verify,
            _params.verbose));
    }

    result = OE_OK;

done:

#if defined(__linux__)
    if (sgx_asem_env == nullptr)
    {
        if (strcmp(INPUT_PARAM_QUOTE_OUT_OF_PROC, _params.quote_proc) == 0 &&
            unsetenv(SGX_AESM_ADDR) != 0)
        {
            printf(
                "Failed to unset environment variable 'SGX_AESM_ADDR', please "
                "manually unset it\n");
            result = OE_FAILURE;
        }
    }
    else if (
        strcmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0 &&
        setenv(SGX_AESM_ADDR, sgx_asem_env, 1) != 0)
    {
        printf(
            "Failed to reset environment variable 'SGX_AESM_ADDR', please "
            "manually reset it as %s\n",
            sgx_asem_env);
        result = OE_FAILURE;
    }
#elif defined(_WIN32)
    if (env_size != 0 &&
        strcmp(INPUT_PARAM_QUOTE_IN_PROC, _params.quote_proc) == 0)
    {
        if (SetEnvironmentVariableA(SGX_AESM_ADDR, sgx_asem_env) == 0)
        {
            printf(
                "Failed to reset environment variable 'SGX_AESM_ADDR', please "
                "manually reset it as %s\n",
                sgx_asem_env);
            result = OE_FAILURE;
        }
    }
#endif
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
    oe_enclave_t* enclave = nullptr;
    char* enclave_filename = nullptr;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("oecert not supported in simulation mode.\n");
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

    if ((result = oe_create_oecert_enclave(
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
