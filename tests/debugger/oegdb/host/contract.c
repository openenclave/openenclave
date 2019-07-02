// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/debugrt/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "../../../../host/sgx/enclave.h"

// The following variables are initialized so that the assertions below will
// fail by default. The test expects the debugger to update the values
// of these variables by introspecting the gdb python plugin.
// If the gdb plugin's assumptions match the layout of the data structures,
// then the assertions won't be triggered.
// volatile is used to prevent compiler-optimizations.
volatile uint64_t OFFSET_MAGIC = (uint64_t)-1;
volatile uint64_t MAGIC_VALUE = (uint64_t)-1;
volatile uint64_t OFFSET_BASE_ADDRESS = (uint64_t)-1;
volatile uint64_t OFFSET_TCS_ARRAY = (uint64_t)-1;
volatile uint64_t OFFSET_NUM_TCS = (uint64_t)-1;
volatile uint64_t OFFSET_DEBUG = (uint64_t)-1;
volatile uint64_t OFFSET_SIMULATE = (uint64_t)-1;
volatile uint64_t OFFSET_NEXT = (uint64_t)-1;

void assert_debugger_binary_contract_host_side()
{
    OE_TEST(OFFSET_MAGIC == OE_OFFSETOF(oe_debug_enclave_t, magic));
    OE_TEST(MAGIC_VALUE == OE_DEBUG_ENCLAVE_MAGIC);

    OE_TEST(
        OFFSET_BASE_ADDRESS == OE_OFFSETOF(oe_debug_enclave_t, base_address));
    OE_TEST(OFFSET_TCS_ARRAY == OE_OFFSETOF(oe_debug_enclave_t, tcs_array));
    OE_TEST(OFFSET_NUM_TCS == OE_OFFSETOF(oe_debug_enclave_t, num_tcs));

    OE_TEST(OFFSET_DEBUG == OE_OFFSETOF(oe_debug_enclave_t, debug));
    OE_TEST(OFFSET_SIMULATE == OE_OFFSETOF(oe_debug_enclave_t, simulate));

    OE_TEST(OFFSET_NEXT == OE_OFFSETOF(oe_debug_enclave_t, next));

    printf("Debugger contract validated on host side.\n");
}
