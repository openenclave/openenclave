// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oe_gdb_test_u.h"

extern void assert_debugger_binary_contract_host_side();

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave1 = NULL;
    bool simulation_mode = false;

    if (argc < 2)
    {
        fprintf(
            stderr, "Usage: %s ENCLAVE_PATH [--simulation-mode]\n", argv[0]);
        return 1;
    }

    uint32_t flags = oe_get_create_flags();

    simulation_mode =
        (argc == 3 && (strcmp(argv[2], "--simulation-mode") == 0));

    if (simulation_mode)
    {
        // Force simulation mode if --simulation-mode is specified.
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if ((result = oe_create_oe_gdb_test_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave1)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    {
        int c = 0;
        OE_TEST(enc_add(enclave1, &c, 5, 6) == OE_OK);

        // Test that the debugger was able to change the return value in the
        // enclave.
        OE_TEST(c == 10000);
    }

    assert_debugger_binary_contract_host_side();
    OE_TEST(enc_assert_debugger_binary_contract(enclave1) == OE_OK);

    // The following magic variable is expected to be set by the debugger
    // after performing a successful walk of the stitched stack.
    volatile uint64_t main_magic = 0;
    OE_TEST(enc_test_stack_stitching(enclave1) == OE_OK);
    // This assertion will fail if the debugger was not able to successfully
    // walk the stack starting at the ocall, back through the ecall and then
    // back to main.
    OE_TEST(main_magic == MAGIC_VALUE);

    result = oe_terminate_enclave(enclave1);
    OE_TEST(result == OE_OK);

    printf(
        "=== passed all tests (oegdb-test%s)\n",
        simulation_mode ? "-simulation-mode" : "");

    return 0;
}

// Do not change the line number of this function. Debugger puts a breakpoint on
// line 84, walks the ocall and ecall stacks and sets the values for the magic
// variables. The assertions would fail if the debugger is not able to walk
// the stack correctly.
void host_function(void)
{
    volatile uint64_t magic_value = MAGIC_VALUE;
    volatile uint64_t host_function_magic = 0;
    // Debugger is expected to set the magic variable.
    OE_TEST(host_function_magic == magic_value);
}
