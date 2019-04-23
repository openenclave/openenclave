// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/error.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "../../../../enclave/core/sgx/td.h"

// These values are filled by the debugger.
// The variables are marked volatile so that the compiler does not hard-code
// the initialization value of the variables in comparision.
// Since 0 could be a legal value for some of these items, they are
// initialized to -1.
volatile uint64_t TD_OFFSET_FROM_TCS = (uint64_t)-1;
volatile uint64_t TD_CALLSITE_OFFSET = (uint64_t)-1;
volatile uint64_t CALLSITE_OCALLCONTEXT_OFFSET = (uint64_t)-1;
volatile uint64_t OCALLCONTEXT_LENGTH = (uint64_t)-1;
volatile char OCALLCONTEXT_FORMAT[10];
volatile uint64_t OCALLCONTEXT_RBP = (uint64_t)-1;
volatile uint64_t OCALLCONTEXT_RET = (uint64_t)-1;

void assert_debugger_binary_contract_enclave_side()
{
    OE_TEST(TD_OFFSET_FROM_TCS == 4 * OE_PAGE_SIZE);
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
