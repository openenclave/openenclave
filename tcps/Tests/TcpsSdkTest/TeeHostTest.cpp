/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/host.h>
#include <sgx.h>
#include "gtest/gtest.h"
#include <TcpsSdkTestTA_u.h>

#ifdef USE_SGX
const char* TA_ID = "TcpsSdkTestTA"; /* DLL will be TcpsSdkTestTA.signed.dll */
#endif
#ifdef USE_OPTEE
const char* TA_ID = "3156152a-19d1-423c-96ea-5adf5675798f";
#endif

TEST(TeeHost, CreateTA_BadId)
{
    // Try to create a non-existent TA.
    sgx_enclave_id_t taid;
    Tcps_StatusCode uStatus = Tcps_CreateTA("acfc9047-a611-4e10-bf65-a7b85a93452d", TCPS_ENCLAVE_FLAG_DEBUG, &taid);
    EXPECT_NE(Tcps_Good, uStatus);

    uStatus = Tcps_CreateTA("abcdef", TCPS_ENCLAVE_FLAG_DEBUG, &taid);
    EXPECT_NE(Tcps_Good, uStatus);
}

TEST(TeeHost, CreateTA_Success)
{
    sgx_enclave_id_t taid;
    sgx_status_t sgxStatus;
    Tcps_StatusCode uStatus = Tcps_CreateTA(TA_ID, TCPS_ENCLAVE_FLAG_DEBUG, &taid);
    ASSERT_EQ(Tcps_Good, uStatus);

    TcpsAcquireTAMutex(taid);
    sgxStatus = ecall_DoNothing(taid, &uStatus);
    TcpsReleaseTAMutex(taid);

    EXPECT_EQ(SGX_SUCCESS, sgxStatus);
    EXPECT_EQ(Tcps_Good, uStatus);

    uStatus = Tcps_DestroyTA(taid);
    EXPECT_EQ(Tcps_Good, uStatus);
}