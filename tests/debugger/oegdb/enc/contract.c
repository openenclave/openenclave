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
volatile uint64_t TD_CALLSITE_OFFSET = (uint64_t)-1;
volatile uint64_t CALLSITE_OCALLCONTEXT_OFFSET = (uint64_t)-1;
volatile uint64_t OCALLCONTEXT_LENGTH = (uint64_t)-1;
volatile char OCALLCONTEXT_FORMAT[10];
volatile uint64_t OCALLCONTEXT_RBP = (uint64_t)-1;
volatile uint64_t OCALLCONTEXT_RET = (uint64_t)-1;

void assert_debugger_binary_contract_enclave_side()
{
    OE_TEST(TCS_GSBASE_OFFSET == OE_OFFSETOF(sgx_tcs_t, gsbase));
    OE_TEST(TD_CALLSITE_OFFSET == OE_OFFSETOF(td_t, callsites));
    OE_TEST(
        CALLSITE_OCALLCONTEXT_OFFSET == OE_OFFSETOF(Callsite, ocall_context));

    OE_TEST(OCALLCONTEXT_LENGTH == sizeof(oe_ocall_context_t));
    OE_TEST(strcmp((const char*)OCALLCONTEXT_FORMAT, "QQ") == 0);
    OE_TEST(
        OCALLCONTEXT_RBP ==
        (OE_OFFSETOF(oe_ocall_context_t, rbp) / sizeof(uint64_t)));
    OE_TEST(
        OCALLCONTEXT_RET ==
        (OE_OFFSETOF(oe_ocall_context_t, ret) / sizeof(uint64_t)));

    printf("Debugger contract validated on enclave side.\n");
}

void enc_assert_debugger_binary_contract()
{
    assert_debugger_binary_contract_enclave_side();
}
