// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#include <openenclave/edger8r/host.h>
#include "TrustedAppTest.h"
#include "TcpsSdkTestTA_u.h"

int ocall_ReturnInputArgument(int input)
{
    return input;
}

class OEEnclaveTest : public TrustedAppTest {
public:
    void* GetEnclave() {
        sgx_enclave_id_t eid = GetTAId();
        void* enclave = (void*)eid;
        return enclave;
    }
};

#include <openenclave/host.h>

TEST_F(OEEnclaveTest, is_within_enclave_Success)
{
    int foo;
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEIsWithinEnclave(GetOEEnclave(), &uStatus, &foo, sizeof(foo));
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, is_outside_enclave_Success)
{
    int foo;
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEIsOutsideEnclave(GetOEEnclave(), &uStatus, &foo, sizeof(foo));
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, random_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOERandom(GetOEEnclave(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, exceptions_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEExceptions(GetOEEnclave(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_report_v1_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetReportV1(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_report_v2_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetReportV2(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_target_info_v1_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetTargetInfoV1(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_target_info_v2_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetTargetInfoV2(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v1_Unique_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV1(GetOEEnclave(), &uStatus, 1);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v2_Unique_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV2(GetOEEnclave(), &uStatus, 1);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v1_Product_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV1(GetOEEnclave(), &uStatus, 2);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v2_Product_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV2(GetOEEnclave(), &uStatus, 2);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v1_BadPolicy_InvalidParameter)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV1(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Bad, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_v2_BadPolicy_InvalidParameter)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = ecall_TestOEGetSealKeyV2(GetOEEnclave(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Bad, uStatus);
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
    oe_buffer256 str;
    COPY_BUFFER_FROM_STRING(str, "hello world");
    oe_result_t oeResult = ecall_OEHostStrndup(GetOEEnclave(), &ptr, str, 5);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);
    EXPECT_EQ(0, strcmp(ptr, "hello"));

    oeResult = ecall_OEHostFree(GetOEEnclave(), ptr);
    EXPECT_EQ(OE_OK, oeResult);
}

TEST_F(OEEnclaveTest, ocall_Success)
{
    Tcps_StatusCode uStatus = Tcps_BadNotImplemented;
    size_t outputSize = 0;
    oe_result_t oeResult = ecall_TestOcall(GetOEEnclave(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}
