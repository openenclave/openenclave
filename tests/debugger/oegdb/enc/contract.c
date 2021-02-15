// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/globals.h>
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

    oe_sgx_td_t* td = oe_sgx_get_td();
    sgx_tcs_t* tcs = (sgx_tcs_t*)td_to_tcs(td);

    // Assert that enclave base address can be computed just from tcs.
    // See: debugger/ptraceLib/enclave_context.c
    if (td->simulate)
    {
        const void* enclave_base_address = __oe_get_enclave_base();
        void* computed_address = (uint8_t*)tcs + OE_PAGE_SIZE - tcs->ossa;
        OE_TEST(enclave_base_address == computed_address);
    }
    else
    {
        // In hardware mode, the first 72 bytes of tcs (includes ossa field)
        // cannot be read. The assertion is skipped.
    }

    printf("Debugger contract validated on enclave side.\n");
}

void enc_assert_debugger_binary_contract()
{
    assert_debugger_binary_contract_enclave_side();
}
