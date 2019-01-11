/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifndef _MSC_VER
#include "sal_unsup.h"
#define __cdecl
#endif
#include "gtest/gtest.h"
#include "TrustedAppTest.h"
#include <openenclave/host.h>
#include "oetests_u.h"

void TrustedAppTest::SetUp()
{
    oe_result_t result = oe_create_oetests_enclave(
        TA_ID,
        OE_ENCLAVE_TYPE_UNDEFINED,
        OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SERIALIZE_ECALLS,
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

oe_enclave_t* TrustedAppTest::GetOEEnclave()
{
    return enclave;
}
