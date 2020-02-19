// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/error.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "../../../../enclave/core/sgx/td.h"

// The following variables are initialized so that the assertions below will
// fail by default. The test expects the debugger to update the values
// of these variables by introspecting the gdb python plugin.
// If the gdb plugin's assumptions match the layout of the data structures,
// then the assertions won't be triggered.
// volatile is used to prevent compiler-optimizations.
volatile uint64_t TCS_GSBASE_OFFSET = (uint64_t)-1;

void assert_debugger_binary_contract_enclave_side()
{
    OE_TEST(TCS_GSBASE_OFFSET == OE_OFFSETOF(sgx_tcs_t, gsbase));

    printf("Debugger contract validated on enclave side.\n");
}

void enc_assert_debugger_binary_contract()
{
    assert_debugger_binary_contract_enclave_side();
}
