/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "gtest/gtest.h"
#include "TrustedAppTest.h"
#include <tcps_u.h>
#include <openenclave/host.h>
#include "TcpsSdkTestTA_u.h"

void TrustedAppTest::SetUp()
{
    oe_result_t result = oe_create_TcpsSdkTestTA_enclave(
        TA_ID,
        OE_ENCLAVE_TYPE_UNDEFINED,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);
    ASSERT_EQ(OE_OK, result);
    EXPECT_TRUE(enclave != NULL);
}

oe_call_t* TrustedAppTest::GetOcallArray(void)
{
    return NULL;
}

uint32_t TrustedAppTest::GetOcallArraySize(void)
{
    return 0;
}

void TrustedAppTest::TearDown() 
{
    oe_result_t result = oe_terminate_enclave(enclave);
    EXPECT_EQ(OE_OK, result);
    enclave = NULL;
}

void TrustedAppTest::AcquireTAMutex() {
    oe_acquire_enclave_mutex(enclave);
}

void TrustedAppTest::ReleaseTAMutex() {
    oe_release_enclave_mutex(enclave);
}

sgx_enclave_id_t TrustedAppTest::GetTAId()
{
    return (sgx_enclave_id_t)enclave;
}

oe_enclave_t* TrustedAppTest::GetOEEnclave()
{
    return enclave;
}
