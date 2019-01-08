/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#include <openenclave/host.h>
extern const char* TA_ID;

class TrustedAppTest : public ::testing::Test {
    protected:
        void SetUp(void) override;
        void TearDown(void) override;
        oe_enclave_t* GetOEEnclave(void);
        virtual oe_call_t* GetOcallArray(void);
        virtual uint32_t GetOcallArraySize(void);

    private:
        oe_enclave_t* enclave;
};
