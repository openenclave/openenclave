// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/error.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "../../../../enclave/core/sgx/td.h"

// Debugger does not rely on any Open Enclave specific data structures on the
// enclave side. It relies only on SGX specific data structures lies sgx_tcs_t.
void assert_debugger_binary_contract_enclave_side()
{
    printf("Debugger contract validated on enclave side.\n");
}

void enc_assert_debugger_binary_contract()
{
    assert_debugger_binary_contract_enclave_side();
}
