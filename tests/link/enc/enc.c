// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

// This enclave does not use any functionality for oeenclave.
// But since it links agains oeenclave, it should retain
// oe_verify_report.
OE_ECALL void Hello(void* arg)
{
    
    void* p = oe_verify_report;
    OE_UNUSED(p);

    OE_UNUSED(arg);
}
