/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifdef LINUX
#include "sal_unsup.h"
#include "stdext.h"
#endif
#include <stddef.h>
#include <string.h>
#include <openenclave/host.h>
#include "oetests_u.h"
#include "gtest/gtest.h"
#include "TrustedAppTest.h"
#include "../../src/Untrusted/TcpsCalls_u.h" // for buffer APIs

TEST(Buffer, CreateReeBuffer_Success)
{
    int originalSize = 7;
    void* hReeBuffer = TcpsCreateReeBuffer(originalSize);
    ASSERT_FALSE(hReeBuffer == NULL);

    char* data;
    int size;
    Tcps_StatusCode uStatus = TcpsGetReeBuffer(hReeBuffer, &data, &size);
    EXPECT_EQ(Tcps_Good, uStatus);
    EXPECT_EQ(originalSize, size);
    ASSERT_FALSE(data == NULL);

    TcpsFreeReeBuffer(hReeBuffer);
}

class BufferTest : public TrustedAppTest {
public:
    void VerifyTeeBufferContents(void* hTeeBuffer, int expectedSize, char* expectedData);
};

void BufferTest::VerifyTeeBufferContents(void* hTeeBuffer, int expectedSize, char* expectedData)
{
    oe_CreateBuffer_Result reeBufferResult = {};
    oe_result_t oeResult = ecall_CreateReeBufferFromTeeBuffer(GetOEEnclave(), &reeBufferResult, hTeeBuffer);
    ASSERT_EQ(OE_OK, oeResult);
    ASSERT_EQ(Tcps_Good, reeBufferResult.uStatus);

    char* actualData;
    int actualSize;
    Tcps_StatusCode uStatus = TcpsGetReeBuffer(reeBufferResult.hBuffer, &actualData, &actualSize);
    EXPECT_EQ(Tcps_Good, uStatus);
    EXPECT_EQ(expectedSize, actualSize);
    ASSERT_FALSE(actualData == NULL);
    ASSERT_EQ(0, memcmp(expectedData, actualData, expectedSize));

    TcpsFreeReeBuffer(reeBufferResult.hBuffer);
}

TEST_F(BufferTest, CreateTeeBuffer_Success)
{
    // Create a 5 byte buffer.
    oe_BufferChunk chunk;
    chunk.size = 5;
    strcpy_s(chunk.buffer, "Test");
    CreateBuffer_Result result;
    oe_acquire_enclave_mutex(GetOEEnclave());
    sgx_status_t sgxStatus = ecall_CreateTeeBuffer(GetTAId(), &result, chunk);
    oe_release_enclave_mutex(GetOEEnclave());
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, result.uStatus);
    ASSERT_FALSE(result.hBuffer == NULL);

    // Read it back to verify the contents.
    VerifyTeeBufferContents(result.hBuffer, chunk.size, chunk.buffer);
    
    oe_acquire_enclave_mutex(GetOEEnclave());
    sgxStatus = ecall_FreeTeeBuffer(GetTAId(), result.hBuffer);
    oe_release_enclave_mutex(GetOEEnclave());
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
}

TEST_F(BufferTest, AppendToTeeBuffer_Success)
{
    // Create a 0 byte buffer.
    oe_BufferChunk chunk = { 0 };
    CreateBuffer_Result result;
    oe_acquire_enclave_mutex(GetOEEnclave());
    sgx_status_t sgxStatus = ecall_CreateTeeBuffer(GetTAId(), &result, chunk);
    oe_release_enclave_mutex(GetOEEnclave());
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, result.uStatus);
    ASSERT_FALSE(result.hBuffer == NULL);

    // Append a 5 byte chunk.
    chunk.size = 5;
    strcpy_s(chunk.buffer, "Test");
    Tcps_StatusCode uStatus;
    oe_acquire_enclave_mutex(GetOEEnclave());
    sgxStatus = ecall_AppendToTeeBuffer(GetTAId(), &uStatus, result.hBuffer, chunk);
    oe_release_enclave_mutex(GetOEEnclave());
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, uStatus);

    // Read it back to verify the contents.
    VerifyTeeBufferContents(result.hBuffer, chunk.size, chunk.buffer);

    oe_acquire_enclave_mutex(GetOEEnclave());
    sgxStatus = ecall_FreeTeeBuffer(GetTAId(), result.hBuffer);
    oe_release_enclave_mutex(GetOEEnclave());

    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
}
