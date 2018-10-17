// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#include <openenclave/edger8r/host.h>
#include "TrustedAppTest.h"
#include "TcpsSdkTestTA_u.h"

void TestOcall(
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    if (input_buffer_size > output_buffer_size) {
        *output_bytes_written = 0;
        return;
    }
    memcpy(output_buffer, input_buffer, input_buffer_size);
    *output_bytes_written = input_buffer_size;
}

class OEEnclaveTest : public TrustedAppTest {
public:
    void* GetEnclave() {
        sgx_enclave_id_t eid = GetTAId();
        void* enclave = (void*)eid;
        return enclave;
    }

    oe_call_t* GetOcallArray() override
    {
        static oe_call_t calls[1] = { TestOcall };
        return calls;
    }

    uint32_t GetOcallArraySize() override
    {
        return 1;
    }
};

#include <openenclave/host.h>

TEST_F(OEEnclaveTest, is_within_enclave_Success)
{
    int foo;
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEIsWithinEnclave(GetTAId(), &uStatus, &foo, sizeof(foo));
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, is_outside_enclave_Success)
{
    int foo;
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEIsOutsideEnclave(GetTAId(), &uStatus, &foo, sizeof(foo));
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, random_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOERandom(GetTAId(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, exceptions_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEExceptions(GetTAId(), &uStatus);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_report_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEGetReport(GetTAId(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_target_info_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEGetTargetInfo(GetTAId(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_Unique_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEGetSealKey(GetTAId(), &uStatus, 1);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_Product_Success)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEGetSealKey(GetTAId(), &uStatus, 2);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Good, uStatus);
}

TEST_F(OEEnclaveTest, get_seal_key_BadPolicy_InvalidParameter)
{
    Tcps_StatusCode uStatus;
    oe_result_t oeResult = (oe_result_t)ecall_TestOEGetSealKey(GetTAId(), &uStatus, 0);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(Tcps_Bad, uStatus);
}

TEST_F(OEEnclaveTest, malloc_Success)
{
    void* ptr;
    oe_result_t oeResult = (oe_result_t)ecall_OEHostMalloc(GetTAId(), &ptr, 15);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);

    void* ptr2;
    oeResult = (oe_result_t)ecall_OEHostRealloc(GetTAId(), &ptr2, ptr, 20);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);

    oeResult = (oe_result_t)ecall_OEHostFree(GetTAId(), ptr2);
    EXPECT_EQ(OE_OK, oeResult);
}

TEST_F(OEEnclaveTest, calloc_Success)
{
    void* ptr;
    oe_result_t oeResult = (oe_result_t)ecall_OEHostCalloc(GetTAId(), &ptr, 5, 3);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);

    oeResult = (oe_result_t)ecall_OEHostFree(GetTAId(), ptr);
    EXPECT_EQ(OE_OK, oeResult);
}

TEST_F(OEEnclaveTest, strndup_Success)
{
    char* ptr;
    buffer256 str;
    COPY_BUFFER_FROM_STRING(str, "hello world");
    oe_result_t oeResult = (oe_result_t)ecall_OEHostStrndup(GetTAId(), &ptr, str, 5);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_TRUE(ptr != NULL);
    EXPECT_EQ(0, strcmp(ptr, "hello"));

    oeResult = (oe_result_t)ecall_OEHostFree(GetTAId(), ptr);
    EXPECT_EQ(OE_OK, oeResult);
}

TEST_F(OEEnclaveTest, ocall_Success)
{
    /* First signal the enclave to register its ecall(s). */
    Tcps_StatusCode uStatus;
    sgx_status_t sgxStatus = ecall_TestOEEcall(GetTAId(), &uStatus);
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, uStatus);

    uStatus = Tcps_BadNotImplemented;
    size_t outputSize = 0;
    oe_result_t oeResult = oe_call_enclave_function(
        GetOEEnclave(),
        1,
        NULL,
        0,
        &uStatus,
        sizeof(uStatus),
        &outputSize);
    EXPECT_EQ(OE_OK, oeResult);
    EXPECT_EQ(sizeof(uStatus), outputSize);
    EXPECT_EQ(Tcps_Good, uStatus);
}
