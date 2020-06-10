// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "../../../../host/sgx/enclave.h"

// The following variables are initialized so that the assertions below will
// fail by default. The test expects the debugger to update the values
// of these variables by introspecting the gdb python plugin.
// If the gdb plugin's assumptions match the layout of the data structures,
// then the assertions won't be triggered.
// volatile is used to prevent compiler-optimizations.
volatile uint64_t OFFSETOF_MAGIC = (uint64_t)-1;
volatile uint64_t SIZEOF_MAGIC = (uint64_t)-1;
volatile uint64_t MAGIC_VALUE = (uint64_t)-1;

volatile uint64_t OFFSETOF_VERSION = (uint64_t)-1;
volatile uint64_t SIZEOF_VERSION = (uint64_t)-1;

volatile uint64_t OFFSETOF_NEXT = (uint64_t)-1;
volatile uint64_t SIZEOF_NEXT = (uint64_t)-1;

volatile uint64_t OFFSETOF_PATH = (uint64_t)-1;
volatile uint64_t SIZEOF_PATH = (uint64_t)-1;

volatile uint64_t OFFSETOF_PATH_LENGTH = (uint64_t)-1;
volatile uint64_t SIZEOF_PATH_LENGTH = (uint64_t)-1;

volatile uint64_t OFFSETOF_BASE_ADDRESS = (uint64_t)-1;
volatile uint64_t SIZEOF_BASE_ADDRESS = (uint64_t)-1;

volatile uint64_t OFFSETOF_SIZE = (uint64_t)-1;
volatile uint64_t SIZEOF_SIZE = (uint64_t)-1;

volatile uint64_t OFFSETOF_TCS_ARRAY = (uint64_t)-1;
volatile uint64_t SIZEOF_TCS_ARRAY = (uint64_t)-1;

volatile uint64_t OFFSETOF_NUM_TCS = (uint64_t)-1;
volatile uint64_t SIZEOF_NUM_TCS = (uint64_t)-1;

volatile uint64_t OFFSETOF_FLAGS = (uint64_t)-1;
volatile uint64_t SIZEOF_FLAGS = (uint64_t)-1;
volatile uint64_t MASK_DEBUG = (uint64_t)-1;
volatile uint64_t MASK_SIMULATE = (uint64_t)-1;

#define OE_SIZEOF(type, member) (sizeof(((type*)0)->member))

void assert_debugger_binary_contract_host_side()
{
    OE_TEST(OFFSETOF_MAGIC == OE_OFFSETOF(oe_debug_enclave_t, magic));
    OE_TEST(SIZEOF_MAGIC == OE_SIZEOF(oe_debug_enclave_t, magic));
    OE_TEST(MAGIC_VALUE == OE_DEBUG_ENCLAVE_MAGIC);

    OE_TEST(OFFSETOF_VERSION == OE_OFFSETOF(oe_debug_enclave_t, version));
    OE_TEST(SIZEOF_VERSION == OE_SIZEOF(oe_debug_enclave_t, version));

    OE_TEST(OFFSETOF_NEXT == OE_OFFSETOF(oe_debug_enclave_t, next));
    OE_TEST(SIZEOF_NEXT == OE_SIZEOF(oe_debug_enclave_t, next));

    OE_TEST(OFFSETOF_PATH == OE_OFFSETOF(oe_debug_enclave_t, path));
    OE_TEST(SIZEOF_PATH == OE_SIZEOF(oe_debug_enclave_t, path));

    OE_TEST(
        OFFSETOF_PATH_LENGTH == OE_OFFSETOF(oe_debug_enclave_t, path_length));
    OE_TEST(SIZEOF_PATH_LENGTH == OE_SIZEOF(oe_debug_enclave_t, path_length));

    OE_TEST(
        OFFSETOF_BASE_ADDRESS == OE_OFFSETOF(oe_debug_enclave_t, base_address));
    OE_TEST(SIZEOF_BASE_ADDRESS == OE_SIZEOF(oe_debug_enclave_t, base_address));

    OE_TEST(OFFSETOF_SIZE == OE_OFFSETOF(oe_debug_enclave_t, size));
    OE_TEST(SIZEOF_SIZE == OE_SIZEOF(oe_debug_enclave_t, size));

    OE_TEST(OFFSETOF_TCS_ARRAY == OE_OFFSETOF(oe_debug_enclave_t, tcs_array));
    OE_TEST(SIZEOF_TCS_ARRAY == OE_SIZEOF(oe_debug_enclave_t, tcs_array));

    OE_TEST(OFFSETOF_NUM_TCS == OE_OFFSETOF(oe_debug_enclave_t, num_tcs));
    OE_TEST(SIZEOF_NUM_TCS == OE_SIZEOF(oe_debug_enclave_t, num_tcs));

    OE_TEST(OFFSETOF_FLAGS == OE_OFFSETOF(oe_debug_enclave_t, flags));
    OE_TEST(SIZEOF_FLAGS == OE_SIZEOF(oe_debug_enclave_t, flags));

    OE_TEST(MASK_DEBUG == OE_DEBUG_ENCLAVE_MASK_DEBUG);
    OE_TEST(MASK_SIMULATE == OE_DEBUG_ENCLAVE_MASK_SIMULATE);

    printf("Debugger contract validated on host side.\n");
}
