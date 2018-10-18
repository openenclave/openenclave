/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "gtest/gtest.h"
#include <openenclave/host.h>
#include <openenclave/edger8r/host.h>
#include <TcpsSdkTestTA_u.h>
#include "TrustedAppTest.h"
#include <openenclave/host.h>
extern const char* TA_ID;

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

TEST(TeeHost, create_enclave_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result = oe_create_enclave(
        TA_ID,
        OE_ENCLAVE_TYPE_UNDEFINED,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        NULL,
        0,
        &enclave);
    ASSERT_EQ(OE_OK, result);
    EXPECT_TRUE(enclave != NULL);

    // Unlike C, C++ requires casts below.  (C just generates warnings.)
    result = (oe_result_t)ecall_DoNothing((sgx_enclave_id_t)enclave, &uStatus);
    EXPECT_EQ(OE_OK, result);
    EXPECT_EQ(Tcps_Good, uStatus);

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
    EXPECT_EQ(OE_OK, oeResult);

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_EQ(OE_OK, oeResult);
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
    EXPECT_EQ(OE_OK, oeResult);

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_EQ(OE_OK, oeResult);

    oe_free_report(report_buffer);
}

TEST_F(OEHostTest, get_target_info_v1_Failed)
{
    oe_result_t oeResult = oe_get_target_info_v1(NULL, 0, NULL, NULL);
    EXPECT_EQ(OE_INVALID_PARAMETER, oeResult);

    sgx_report_t sgx_report = { 0 };
    size_t size = 0;
    oeResult = oe_get_target_info_v1((uint8_t*)&sgx_report, sizeof(sgx_report), NULL, &size);
    EXPECT_EQ(OE_BUFFER_TOO_SMALL, oeResult);
    EXPECT_TRUE(size > 0);
}

TEST_F(OEHostTest, get_target_info_v2_Failed)
{
    oe_result_t oeResult = oe_get_target_info_v2(NULL, 0, NULL, NULL);
    EXPECT_EQ(OE_INVALID_PARAMETER, oeResult);
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

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_EQ(OE_OK, oeResult);
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

    oeResult = oe_verify_report(GetOEEnclave(), report_buffer, report_buffer_size, NULL);
    EXPECT_EQ(OE_OK, oeResult);
    oe_free_report(report_buffer);
}

TEST_F(OEHostTest, ecall_Success)
{
    /* First signal the enclave to register its ecall(s). */
    Tcps_StatusCode uStatus;
    sgx_status_t sgxStatus = ecall_TestOEEcall(GetTAId(), &uStatus);
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, uStatus);

    int input = 1;
    int output = 0;
    size_t outputSize = 0;
    oe_result_t oeResult = oe_call_enclave_function(
        GetOEEnclave(),
        0,
        &input,
        sizeof(input),
        &output,
        sizeof(output),
        &outputSize);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(sizeof(output), outputSize);
    EXPECT_EQ(input, output);
}
