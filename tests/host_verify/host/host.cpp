// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <fcntl.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/host_verify.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../../../common/sgx/quote.h"
#include "../../../host/sgx/sgxquoteprovider.h"

#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <io.h>
#else
#error "Unsupported OS platform"
#endif

#define MAX_CERT_SIZE 8192
#define CERT_EC_FILENAME "sgx_cert_ec.der"
#define CERT_RSA_FILENAME "sgx_cert_rsa.der"
#define CERT_EC_BAD_FILENAME "sgx_cert_ec_bad.der"
#define CERT_RSA_BAD_FILENAME "sgx_cert_rsa_bad.der"

#define REPORT_FILENAME "sgx_report.bin"
#define REPORT_BAD_FILENAME "sgx_report_bad.bin"

oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    OE_UNUSED(arg);

    OE_TRACE_INFO(
        "Enclave certificate contains the following identity information:\n");
    OE_TRACE_INFO(
        "identity.security_version = %d\n", identity->security_version);

    OE_TRACE_INFO("identity->unique_id :\n");
    for (int i = 0; i < 32; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->unique_id[i]);

    OE_TRACE_INFO("\nidentity->signer_id :\n");
    for (int i = 0; i < 32; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < 16; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    return OE_OK;
}

static bool _validate_file(const char* filename, bool assert)
{
    FILE* fp;
#ifdef _WIN32
    fopen_s(&fp, filename, "rb");
#else
    fp = fopen(filename, "rb");
#endif

    if (assert)
        OE_TEST(fp != NULL);

    if (fp)
        fclose(fp);

    return (fp != NULL);
}

static oe_result_t _verify_cert(const char* filename, bool pass)
{
    FILE* fp = NULL;
    oe_result_t oe_ret = OE_FAILURE;

    uint8_t buf[MAX_CERT_SIZE];
    size_t bytes_read;

    OE_TRACE_INFO("\n\nLoading and verifying %s\n\n", filename);
#ifdef _WIN32
    fopen_s(&fp, filename, "rb");
#else
    fp = fopen(filename, "rb");
#endif
    OE_TEST(fp != NULL);

    bytes_read = fread(buf, sizeof(uint8_t), sizeof(buf), fp);
    OE_TEST(bytes_read > 0);

    oe_ret = oe_verify_attestation_certificate(
        buf, bytes_read, enclave_identity_verifier, NULL);
    if (pass)
        OE_TEST(oe_ret == OE_OK);
    else
    {
        // Note: Failure results are different when running in linux vs windows.
        OE_TEST(oe_ret != OE_OK);
        OE_TRACE_INFO(
            "Cert %s verification failed as expected. Failure %d(%s)\n",
            filename,
            oe_ret,
            oe_result_str(oe_ret));
    }

    OE_TRACE_INFO("\n\nSuccess in verifying %s!\n", filename);

    if (fp != NULL)
        fclose(fp);

    return oe_ret;
}

static size_t _get_filesize(FILE* fp)
{
    size_t size = 0;
    fseek(fp, 0, SEEK_END);
    size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    return size;
}

static void _read_binary_file(
    const char* filename,
    uint8_t** data_ptr,
    size_t* size_ptr)
{
    FILE* fp;
#ifdef _WIN32
    fopen_s(&fp, filename, "rb");
#else
    fp = fopen(filename, "rb");
#endif
    size_t size = 0;
    uint8_t* data = NULL;

    if (fp == NULL)
        OE_TRACE_ERROR("Failed to find file: %s\n", filename);
    OE_TEST(fp != NULL);

    // Find file size
    size = _get_filesize(fp);

    data = (uint8_t*)malloc(size);
    OE_TEST(data != NULL);

    size_t bytes_read = fread(data, sizeof(uint8_t), size, fp);
    OE_TEST(bytes_read == size);

    if (fp)
        fclose(fp);

    *data_ptr = data;
    *size_ptr = bytes_read;
}

static int _verify_report(
    const char* report_filename,
    const char* endorsements_filename,
    bool pass)
{
    int ret = -1;
    size_t report_file_size = 0;
    size_t endorsements_file_size = 0;
    uint8_t* report_data = NULL;
    uint8_t* endorsements_data = NULL;
    oe_result_t result = OE_FAILURE;

    OE_TRACE_INFO(
        "\n\nVerifying report %s, endorsements: %s\n",
        report_filename,
        endorsements_filename);

    _read_binary_file(report_filename, &report_data, &report_file_size);

    if (endorsements_filename == NULL)
    {
        result = oe_verify_remote_report(
            report_data, report_file_size, NULL, 0, NULL);
        if (pass)
            OE_TEST(result == OE_OK);
        else
        {
            // Note: The failure result code is different between linux vs
            // windows.
            //
            OE_TEST(result != OE_OK);
            OE_TRACE_INFO(
                "Report %s verification failed as expected. Failure %d(%s)\n",
                report_filename,
                result,
                oe_result_str(result));
        }

        OE_TRACE_INFO("Report %s verified successfully!\n\n", report_filename);
    }
    else
    {
        _read_binary_file(
            endorsements_filename, &endorsements_data, &endorsements_file_size);

        result = oe_verify_remote_report(
            report_data,
            report_file_size,
            endorsements_data,
            endorsements_file_size,
            NULL);
        if (pass)
            OE_TEST(result == OE_OK);
        else
        {
            // Note: The failure result code is different between linux vs
            // windows.
            //
            OE_TEST(result != OE_OK);
            OE_TRACE_INFO(
                "Report %s verification failed as expected. The generated "
                "endorsement file is %s. Failure %d(%s)\n",
                report_filename,
                endorsements_filename,
                result,
                oe_result_str(result));
        }

        result = oe_verify_sgx_quote(
            report_data,
            report_file_size,
            endorsements_data,
            endorsements_file_size,
            NULL);

        if (pass)
            OE_TEST(result == OE_OK);
        else
        {
            // Note: The failure result code is different between linux vs
            // windows.
            //
            OE_TEST(result != OE_OK);
            OE_TRACE_INFO(
                "Report %s and collateral %s verification failed as expected. "
                "Failure %d(%s)\n",
                report_filename,
                endorsements_filename,
                result,
                oe_result_str(result));
        }

        OE_TRACE_INFO("Report %s verified successfully!\n\n", report_filename);
    }
    ret = 0;

    if (report_data != NULL)
        free(report_data);
    if (endorsements_data != NULL)
        free(endorsements_data);

    return ret;
}

int main()
{
    //
    // Report only tests
    //

    // These files are generated by oecert and do not always exists.
    // Run these tests if the file exists.  The Jenkins CI/CD system
    // is responsible for running oecert to generate these files.
    //
    if (_validate_file(CERT_EC_FILENAME, false))
        _verify_cert(CERT_EC_FILENAME, true);

    if (_validate_file(CERT_RSA_FILENAME, false))
        _verify_cert(CERT_RSA_FILENAME, true);

    if (_validate_file(REPORT_FILENAME, false))
        _verify_report(REPORT_FILENAME, NULL, true);

    // These files are checked in and should always exist.
    if (_validate_file(CERT_EC_BAD_FILENAME, true))
        _verify_cert(CERT_EC_BAD_FILENAME, false);

    if (_validate_file(CERT_RSA_BAD_FILENAME, true))
        _verify_cert(CERT_RSA_BAD_FILENAME, false);

    if (_validate_file(REPORT_BAD_FILENAME, true))
        _verify_report(REPORT_BAD_FILENAME, NULL, false);

    return 0;
}
