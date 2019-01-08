// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#ifndef _MSC_VER
#include "sal_unsup.h"
#include "stdext.h"
#endif
#include "gtest/gtest.h"
#include <openenclave/host.h>
#include "TrustedAppTest.h"
#include "oetests_u.h"

void ocall_DoNothing(void)
{
}

int ocall_ReturnInputArgument(int input)
{
    return input;
}

void ocall_PrintString(const char* fmt, const char* arg)
{
    printf(fmt, arg);
}

int ocall_BufferToInt(const void* buffer, size_t size)
{
    int output;
    if (size != sizeof(int)) {
        return -1;
    }
    memcpy(&output, buffer, size);
    return output;
}

class OEEnclaveTest : public TrustedAppTest {
};

#include <openenclave/host.h>

TEST_F(OEEnclaveTest, is_within_enclave_Success)
{
    int foo;
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEIsWithinEnclave(GetOEEnclave(), &uStatus, &foo, sizeof(foo));
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, is_outside_enclave_Success)
{
    int foo;
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEIsOutsideEnclave(GetOEEnclave(), &uStatus, &foo, sizeof(foo));
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, random_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOERandom(GetOEEnclave(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, exceptions_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEExceptions(GetOEEnclave(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_report_v1_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetReportV1(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_report_v2_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetReportV2(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_target_info_v1_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetTargetInfoV1(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_target_info_v2_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetTargetInfoV2(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v1_Unique_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV1(GetOEEnclave(), &uStatus, 1);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v2_Unique_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV2(GetOEEnclave(), &uStatus, 1);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v1_Product_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV1(GetOEEnclave(), &uStatus, 2);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v2_Product_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV2(GetOEEnclave(), &uStatus, 2);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v1_BadPolicy_InvalidParameter)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV1(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_FAILURE, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v2_BadPolicy_InvalidParameter)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV2(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_FAILURE, uStatus);
}

TEST_F(OEEnclaveTest, get_public_key_Unique_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetPublicKey(GetOEEnclave(), &uStatus, 1);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_public_key_Product_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetPublicKey(GetOEEnclave(), &uStatus, 2);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_public_key_BadPolicy_InvalidParameter)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetPublicKey(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_INVALID_PARAMETER, uStatus);
}

TEST_F(OEEnclaveTest, get_private_key_Unique_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetPrivateKey(GetOEEnclave(), &uStatus, 1);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_private_key_Product_Success)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetPrivateKey(GetOEEnclave(), &uStatus, 2);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, get_private_key_v2_BadPolicy_InvalidParameter)
{
    oe_result_t uStatus;
    oe_result_t oeResult = ecall_TestOEGetPrivateKey(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_INVALID_PARAMETER, uStatus);
}

TEST_F(OEEnclaveTest, malloc_Success)
{
    void* ptr;
    oe_result_t oeResult = ecall_OEHostMalloc(GetOEEnclave(), &ptr, 15);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);

    void* ptr2;
    oeResult = ecall_OEHostRealloc(GetOEEnclave(), &ptr2, ptr, 20);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);

    oeResult = ecall_OEHostFree(GetOEEnclave(), ptr2);
    EXPECT_EQ(OE_OK, oeResult);
}

TEST_F(OEEnclaveTest, calloc_Success)
{
    void* ptr;
    oe_result_t oeResult = ecall_OEHostCalloc(GetOEEnclave(), &ptr, 5, 3);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);

    oeResult = ecall_OEHostFree(GetOEEnclave(), ptr);
    EXPECT_EQ(OE_OK, oeResult);
}

TEST_F(OEEnclaveTest, strndup_Success)
{
    char* ptr;
    oe_result_t oeResult = ecall_OEHostStrndup(GetOEEnclave(), &ptr, "hello world", 5);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);
    EXPECT_EQ(0, strcmp(ptr, "hello"));

    oeResult = ecall_OEHostFree(GetOEEnclave(), ptr);
    EXPECT_EQ(OE_OK, oeResult);
}

TEST_F(OEEnclaveTest, ocall_Success)
{
    oe_result_t uStatus = OE_UNSUPPORTED;
    size_t outputSize = 0;
    oe_result_t oeResult = ecall_TestOcall(GetOEEnclave(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, uStatus);
}

TEST_F(OEEnclaveTest, string_calls_Success)
{
    int result;
    oe_result_t oeResult = ecall_PrintString(GetOEEnclave(), &result, "%s", "Hello World\n");
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, result);
}

TEST_F(OEEnclaveTest, buffer_calls_Success)
{
    int input = 0x01020304;
    int output = 0;
    int result;
    oe_result_t oeResult = ecall_BufferToInt(GetOEEnclave(), &result, &output, &input, sizeof(input));
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, result);
    EXPECT_EQ(0x01020304, output);
}

TEST_F(OEEnclaveTest, inout_calls_Success)
{
    int input = 42;
    int output = 0;
    oe_result_t oeResult = ecall_CopyInt(GetOEEnclave(), &input, &output);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(42, input);
    EXPECT_EQ(42, output);
}

TEST_F(OEEnclaveTest, fopen_Success)
{
    oe_result_t apiResult;
    oe_result_t oeResult = ecall_TestOEFopen(GetOEEnclave(), &apiResult);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(OE_OK, apiResult);
}
