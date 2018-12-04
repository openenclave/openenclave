/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifdef LINUX
#include "sal_unsup.h"
#define sprintf_s(str, sz, ...) sprintf(str, __VA_ARGS__)
#endif

#include "gtest/gtest.h"

/* Allow deprecated APIs in this file, since we need to test them. */
#define OE_ALLOW_DEPRECATED_APIS
#include <openenclave/host.h>
#include "oetests_u.h"
#include "TrustedAppTest.h"

#ifdef OE_USE_SGX
const char* TA_ID = "oetests_enclave"; /* DLL will be oetests_enclave.signed.dll */
#define EXPECT_OPTEE_SGX_DIFFERENCE(sgx, optee, oeResult)   EXPECT_EQ(sgx, oeResult);
#endif
#ifdef OE_USE_OPTEE
const char* TA_ID = "3156152a-19d1-423c-96ea-5adf5675798f";
#define EXPECT_OPTEE_SGX_DIFFERENCE(sgx, optee, oeResult)   EXPECT_EQ(optee, oeResult);
#endif

TEST(TeeHost, create_enclave_BadId)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    // Try to create a non-existent TA.
    result = oe_create_enclave(
        "acfc9047-a611-4e10-bf65-a7b85a93452d",
        OE_ENCLAVE_TYPE_UNDEFINED,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        NULL,
        0,
        &enclave);
    EXPECT_NE(OE_OK, result);
    EXPECT_TRUE(enclave == NULL);

    result = oe_create_enclave(
        "abcdef",
        OE_ENCLAVE_TYPE_UNDEFINED,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        NULL,
        0,
        &enclave);
    EXPECT_NE(OE_OK, result);
    EXPECT_TRUE(enclave == NULL);
}

TEST(TeeHost, create_enclave_NoSuffix_Success)
{
    oe_result_t uStatus = OE_OK;
    oe_result_t result = OE_OK;
    oe_enclave_t* enclave = NULL;

    result = oe_create_oetests_enclave(
        TA_ID,
        OE_ENCLAVE_TYPE_UNDEFINED,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);
    ASSERT_EQ(OE_OK, result);
    EXPECT_TRUE(enclave != NULL);

    result = ecall_DoNothing(enclave);
    EXPECT_EQ(OE_OK, result);

    result = ecall_ReturnOk(enclave, &uStatus);
    EXPECT_EQ(OE_OK, result);
    EXPECT_EQ(OE_OK, uStatus);

    result = oe_terminate_enclave(enclave);
    EXPECT_EQ(OE_OK, result);
}

TEST(TeeHost, create_enclave_Suffix_Success)
{
    oe_result_t uStatus = OE_OK;
    oe_result_t result = OE_OK;
    oe_enclave_t* enclave = NULL;
    char ta_filename[256];
    sprintf_s(ta_filename, sizeof(ta_filename),
#ifdef OE_USE_OPTEE
        "%s.ta",
#else
        "%s.signed.dll",
#endif
        TA_ID);

    result = oe_create_oetests_enclave(
        ta_filename,
        OE_ENCLAVE_TYPE_UNDEFINED,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);
    ASSERT_EQ(OE_OK, result);
    EXPECT_TRUE(enclave != NULL);

    result = ecall_DoNothing(enclave);
    EXPECT_EQ(OE_OK, result);

    result = ecall_ReturnOk(enclave, &uStatus);
    EXPECT_EQ(OE_OK, result);
    EXPECT_EQ(OE_OK, uStatus);

    result = oe_terminate_enclave(enclave);
    EXPECT_EQ(OE_OK, result);
}

class OEHostTest : public TrustedAppTest {
};

TEST_F(OEHostTest, get_report_v1_Success)
{
    uint8_t report_buffer[1024];
    size_t report_buffer_size = sizeof(report_buffer);

    oe_result_t oeResult = oe_get_report_v1(GetOEEnclave(),
                                            0,
                                            NULL, // opt_params,
                                            0,    // opt_params_size,
                                            report_buffer,
                                            &report_buffer_size);
    EXPECT_EQ(OE_OK, oeResult);

    oe_report_t parsed_report;
    oeResult = oe_parse_report(report_buffer, report_buffer_size, &parsed_report);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_OK, OE_UNSUPPORTED, oeResult);

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_OK, OE_UNSUPPORTED, oeResult);
}

TEST_F(OEHostTest, get_report_v2_Success)
{
    uint8_t* report_buffer;
    size_t report_buffer_size = sizeof(report_buffer);

    oe_result_t oeResult = oe_get_report_v2(GetOEEnclave(),
                                            0,
                                            NULL, // opt_params,
                                            0,    // opt_params_size,
                                            &report_buffer,
                                            &report_buffer_size);
    EXPECT_EQ(OE_OK, oeResult);

    oe_report_t parsed_report;
    oeResult = oe_parse_report(report_buffer, report_buffer_size, &parsed_report);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_OK, OE_UNSUPPORTED, oeResult);

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_OK, OE_UNSUPPORTED, oeResult);

    oe_free_report(report_buffer);
}

TEST_F(OEHostTest, get_target_info_v1_Failed)
{
    oe_result_t oeResult = oe_get_target_info_v1(NULL, 0, NULL, NULL);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_INVALID_PARAMETER, OE_UNSUPPORTED, oeResult);

    uint8_t report[1024];
    size_t size = 0;
    oeResult = oe_get_target_info_v1(report, sizeof(report), NULL, &size);
#if defined(OE_USE_OPTEE)
    EXPECT_EQ(OE_UNSUPPORTED, oeResult);
#else
    EXPECT_EQ(OE_BUFFER_TOO_SMALL, oeResult);
    EXPECT_TRUE(size > 0);
#endif
}

TEST_F(OEHostTest, get_target_info_v2_Failed)
{
    oe_result_t oeResult = oe_get_target_info_v2(NULL, 0, NULL, NULL);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_INVALID_PARAMETER, OE_UNSUPPORTED, oeResult);
}

TEST_F(OEHostTest, get_target_info_v1_Success)
{
    uint8_t report_buffer[1024];
    size_t report_buffer_size = sizeof(report_buffer);

    oe_result_t oeResult = oe_get_report_v1(GetOEEnclave(),
        0,
        NULL, // opt_params,
        0,    // opt_params_size,
        report_buffer,
        &report_buffer_size);
    EXPECT_EQ(OE_OK, oeResult);

    /* Get target info size. */
    size_t targetInfoSize = 0;
    oeResult = oe_get_target_info_v1(report_buffer, report_buffer_size, NULL, &targetInfoSize);
#if defined(OE_USE_OPTEE)
    EXPECT_EQ(OE_UNSUPPORTED, oeResult);
#else
    EXPECT_EQ(OE_BUFFER_TOO_SMALL, oeResult);
    EXPECT_TRUE(targetInfoSize > 0);

    uint8_t* targetInfo = (uint8_t*)malloc(targetInfoSize);
    ASSERT_TRUE(targetInfo != NULL);

    oeResult = oe_get_target_info_v1(report_buffer, report_buffer_size, targetInfo, &targetInfoSize);
    EXPECT_EQ(OE_OK, oeResult);

    oeResult = oe_get_report_v1(GetOEEnclave(),
        0,
        targetInfo,
        targetInfoSize,
        report_buffer,
        &report_buffer_size);
    EXPECT_EQ(OE_OK, oeResult);

    free(targetInfo);
#endif

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_OK, OE_UNSUPPORTED, oeResult);
}

TEST_F(OEHostTest, get_target_info_v2_Success)
{
    uint8_t* report_buffer;
    size_t report_buffer_size = sizeof(report_buffer);

    oe_result_t oeResult = oe_get_report_v2(GetOEEnclave(),
        0,
        NULL, // opt_params,
        0,    // opt_params_size,
        &report_buffer,
        &report_buffer_size);
    EXPECT_EQ(OE_OK, oeResult);

    void* targetInfo = NULL;
    size_t targetInfoSize = 0;
    oeResult = oe_get_target_info_v2(report_buffer, report_buffer_size, &targetInfo, &targetInfoSize);
#if defined(OE_USE_OPTEE)
    EXPECT_EQ(OE_UNSUPPORTED, oeResult);
#else
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(targetInfoSize > 0);
    ASSERT_TRUE(targetInfo != NULL);
    oe_free_report(report_buffer);

    oeResult = oe_get_report_v2(GetOEEnclave(),
        0,
        targetInfo,
        targetInfoSize,
        &report_buffer,
        &report_buffer_size);
    EXPECT_EQ(OE_OK, oeResult);

    oe_free_target_info(targetInfo);
#endif

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_OPTEE_SGX_DIFFERENCE(OE_OK, OE_UNSUPPORTED, oeResult);
    oe_free_report(report_buffer);
}

TEST_F(OEHostTest, ecall_Success)
{
    oe_result_t oeResult = ecall_DoNothing(GetOEEnclave());
    EXPECT_EQ(OE_OK, oeResult);
}
