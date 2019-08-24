// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <fcntl.h>
#include <limits.h>
#include <openenclave/host_verify.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_CERT_SIZE 8192
#define CERT_EC_FILENAME "sgx_cert_ec.der"
#define CERT_RSA_FILENAME "sgx_cert_rsa.der"
#define CERT_EC_BAD_TCB_FILENAME "sgx_cert_ec_bad_tcb.der"
#define CERT_RSA_BAD_TCB_FILENAME "sgx_cert_rsa_bad_tcb.der"

#define REPORT_FILENAME "sgx_report.bin"
#define REPORT_BAD_TCB_FILENAME "sgx_report_bad_tcb.bin"

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

static oe_result_t _verify_cert(
    const char* filename,
    oe_result_t expected_result)
{
    FILE* fp = NULL;
    oe_result_t oe_ret = OE_FAILURE;

    uint8_t buf[MAX_CERT_SIZE];
    size_t bytes_read;

    OE_TRACE_INFO("\n\nLoading and verifying %s\n\n", filename);

    fp = fopen(filename, "r");
    OE_TEST(fp != NULL);

    bytes_read = fread(buf, sizeof(uint8_t), sizeof(buf), fp);
    OE_TEST(bytes_read > 0);

    oe_ret = oe_verify_attestation_certificate(
        buf, bytes_read, enclave_identity_verifier, NULL);
    OE_TEST(oe_ret == expected_result);

    OE_TRACE_INFO("\n\nSuccess in verifying %s!\n", filename);

    if (fp != NULL)
        fclose(fp);

    return oe_ret;
}

static int _verify_report(
    const char* report_filename,
    oe_result_t expected_result)
{
    FILE* report_fp = NULL;
    int ret = -1;
    size_t file_size = 0;
    uint8_t* data = NULL;
    oe_result_t result = OE_FAILURE;

    OE_TRACE_INFO("\n\nVerifying report %s\n", report_filename);
    report_fp = fopen(report_filename, "r");
    OE_TEST(report_fp != NULL);

    // Find file size
    fseek(report_fp, 0, SEEK_END);
    file_size = (size_t)ftell(report_fp);
    fseek(report_fp, 0, SEEK_SET);

    data = (uint8_t*)malloc((size_t)file_size);
    OE_TEST(data != NULL);

    OE_TEST(fread(data, sizeof(uint8_t), file_size, report_fp) == file_size);

    result = oe_verify_remote_report(data, file_size, NULL);
    OE_TEST(result == expected_result);

    OE_TRACE_INFO("Report %s verified successfully!\n\n", report_filename);
    ret = 0;

    if (report_fp != NULL)
        fclose(report_fp);

    if (data != NULL)
        free(data);

    return ret;
}

int main()
{
    _verify_report(REPORT_FILENAME, OE_OK);
    _verify_report(REPORT_BAD_TCB_FILENAME, OE_TCB_LEVEL_INVALID);

    _verify_cert(CERT_EC_FILENAME, OE_OK);
    _verify_cert(CERT_RSA_FILENAME, OE_OK);
    _verify_cert(CERT_EC_BAD_TCB_FILENAME, OE_TCB_LEVEL_INVALID);
    _verify_cert(CERT_RSA_BAD_TCB_FILENAME, OE_TCB_LEVEL_INVALID);

    return 0;
}
