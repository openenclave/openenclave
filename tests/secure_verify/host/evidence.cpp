// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "evidence.h"

#include <ctype.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/tests.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secure_verify_u.h"

#if defined(__linux__)
#include <dlfcn.h>
#else
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
#include <openssl/applink.c>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#endif

#include "../../../common/attest_plugin.h"
#include "../../../common/sgx/collateral.h"
#include "../../../common/sgx/quote.h"
#include "../../../host/sgx/sgxquoteprovider.h"

extern FILE* log_file;

void log(const char* fmt, ...)
{
    char message[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    // ensure buf is always null-terminated
    message[sizeof(message) - 1] = 0;

    if (log_file)
    {
        fprintf(log_file, "%s", message);
    }
    else
    {
        printf("%s", message);
    }
}

// DCAP client (libdcap_quoteprov) log callback to this function.
void secure_verify_quote_provider_log(
    sgx_ql_log_level_t level,
    const char* message)
{
    const char* level_string = level == 0 ? "ERROR" : "INFO";

    log("[%s]: %s\n", level_string, message);
}

// Set DCAP client (libdcap_quoteprov) log callback
void set_log_callback()
{
#if defined(__linux__)
    extern oe_sgx_quote_provider_t provider;

    // Initialize quote provider and set log callback
    oe_initialize_quote_provider();

    sgx_ql_set_logging_function_t set_log_fcn =
        (sgx_ql_set_logging_function_t)dlsym(
            provider.handle, "sgx_ql_set_logging_function");
    if (set_log_fcn != nullptr)
    {
        set_log_fcn(secure_verify_quote_provider_log);
    }
#endif
}

size_t get_filesize(FILE* fp)
{
    size_t size = 0;
    fseek(fp, 0, SEEK_END);
    size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    return size;
}

bool read_binary_file(
    const char* filename,
    uint8_t** data_ptr,
    size_t* size_ptr)
{
    size_t size = 0;
    uint8_t* data = NULL;
    size_t bytes_read = 0;
    bool result = false;
    FILE* fp = NULL;
#ifdef _WIN32
    if (fopen_s(&fp, filename, "rb") != 0)
#else
    if (!(fp = fopen(filename, "rb")))
#endif
    {
        fprintf(stderr, "Failed to open: %s\n", filename);
        goto exit;
    }

    *data_ptr = NULL;
    *size_ptr = 0;

    // Find file size
    size = get_filesize(fp);
    if (size == 0)
    {
        fprintf(stderr, "Empty file: %s\n", filename);
        goto exit;
    }

    data = (uint8_t*)malloc(size);
    if (data == NULL)
    {
        fprintf(
            stderr,
            "Failed to allocate memory of size %lu\n",
            (unsigned long)size);
        goto exit;
    }

    bytes_read = fread(data, sizeof(uint8_t), size, fp);
    if (bytes_read != size)
    {
        fprintf(stderr, "Failed to read file: %s\n", filename);
        goto exit;
    }

    result = true;

exit:
    if (fp)
    {
        fclose(fp);
    }

    if (!result)
    {
        if (data != NULL)
        {
            free(data);
            data = NULL;
        }
        bytes_read = 0;
    }

    *data_ptr = data;
    *size_ptr = bytes_read;

    return result;
}

oe_result_t verify_oe_evidence(
    oe_enclave_t* enclave,
    const oe_uuid_t* foramt_id,
    const char* evidence_filename,
    const char* endorsement_filename)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t evidence_file_size = 0;
    uint8_t* evidence_data = NULL;

    size_t endorsement_file_size = 0;
    uint8_t* endorsement_data = NULL;

    if (!read_binary_file(
            evidence_filename, &evidence_data, &evidence_file_size))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (endorsement_filename &&
        !read_binary_file(
            endorsement_filename, &endorsement_data, &endorsement_file_size))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    verify_plugin_evidence(
        enclave,
        &result,
        foramt_id,
        evidence_data,
        evidence_file_size,
        endorsement_data,
        endorsement_file_size);

    OE_CHECK_MSG(
        result,
        "Failed to verify_plugin_evidence. Error: %s\n",
        oe_result_str(result));

    result = OE_OK;

done:
    free(evidence_data);
    return result;
}
