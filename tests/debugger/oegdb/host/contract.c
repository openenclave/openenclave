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
volatile uint64_t ENCLAVE_OFFSETOF_MAGIC = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_MAGIC = (uint64_t)-1;
volatile uint64_t ENCLAVE_MAGIC_VALUE = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_VERSION = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_VERSION = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_NEXT = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_NEXT = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_PATH = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_PATH = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_PATH_LENGTH = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_PATH_LENGTH = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_BASE_ADDRESS = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_BASE_ADDRESS = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_SIZE = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_SIZE = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_TCS_ARRAY = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_TCS_ARRAY = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_TCS_COUNT = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_TCS_COUNT = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_FLAGS = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_FLAGS = (uint64_t)-1;
volatile uint64_t ENCLAVE_MASK_DEBUG = (uint64_t)-1;
volatile uint64_t ENCLAVE_MASK_SIMULATE = (uint64_t)-1;

volatile uint64_t ENCLAVE_OFFSETOF_MODULES = (uint64_t)-1;
volatile uint64_t ENCLAVE_SIZEOF_MODULES = (uint64_t)-1;

volatile uint64_t MODULE_OFFSETOF_MAGIC = (uint64_t)-1;
volatile uint64_t MODULE_SIZEOF_MAGIC = (uint64_t)-1;
volatile uint64_t MODULE_MAGIC_VALUE = (uint64_t)-1;

volatile uint64_t MODULE_OFFSETOF_VERSION = (uint64_t)-1;
volatile uint64_t MODULE_SIZEOF_VERSION = (uint64_t)-1;

volatile uint64_t MODULE_OFFSETOF_NEXT = (uint64_t)-1;
volatile uint64_t MODULE_SIZEOF_NEXT = (uint64_t)-1;

volatile uint64_t MODULE_OFFSETOF_PATH = (uint64_t)-1;
volatile uint64_t MODULE_SIZEOF_PATH = (uint64_t)-1;

volatile uint64_t MODULE_OFFSETOF_PATH_LENGTH = (uint64_t)-1;
volatile uint64_t MODULE_SIZEOF_PATH_LENGTH = (uint64_t)-1;

volatile uint64_t MODULE_OFFSETOF_BASE_ADDRESS = (uint64_t)-1;
volatile uint64_t MODULE_SIZEOF_BASE_ADDRESS = (uint64_t)-1;

volatile uint64_t MODULE_OFFSETOF_SIZE = (uint64_t)-1;
volatile uint64_t MODULE_SIZEOF_SIZE = (uint64_t)-1;

#define OE_SIZEOF(type, member) (sizeof(((type*)0)->member))

void assert_debugger_binary_contract_host_side()
{
    /* oe_debug_enclave_t */
    OE_TEST(ENCLAVE_OFFSETOF_MAGIC == OE_OFFSETOF(oe_debug_enclave_t, magic));
    OE_TEST(ENCLAVE_SIZEOF_MAGIC == OE_SIZEOF(oe_debug_enclave_t, magic));
    OE_TEST(ENCLAVE_MAGIC_VALUE == OE_DEBUG_ENCLAVE_MAGIC);

    OE_TEST(
        ENCLAVE_OFFSETOF_VERSION == OE_OFFSETOF(oe_debug_enclave_t, version));
    OE_TEST(ENCLAVE_SIZEOF_VERSION == OE_SIZEOF(oe_debug_enclave_t, version));

    OE_TEST(ENCLAVE_OFFSETOF_NEXT == OE_OFFSETOF(oe_debug_enclave_t, next));
    OE_TEST(ENCLAVE_SIZEOF_NEXT == OE_SIZEOF(oe_debug_enclave_t, next));

    OE_TEST(ENCLAVE_OFFSETOF_PATH == OE_OFFSETOF(oe_debug_enclave_t, path));
    OE_TEST(ENCLAVE_SIZEOF_PATH == OE_SIZEOF(oe_debug_enclave_t, path));

    OE_TEST(
        ENCLAVE_OFFSETOF_PATH_LENGTH ==
        OE_OFFSETOF(oe_debug_enclave_t, path_length));
    OE_TEST(
        ENCLAVE_SIZEOF_PATH_LENGTH ==
        OE_SIZEOF(oe_debug_enclave_t, path_length));

    OE_TEST(
        ENCLAVE_OFFSETOF_BASE_ADDRESS ==
        OE_OFFSETOF(oe_debug_enclave_t, base_address));
    OE_TEST(
        ENCLAVE_SIZEOF_BASE_ADDRESS ==
        OE_SIZEOF(oe_debug_enclave_t, base_address));

    OE_TEST(ENCLAVE_OFFSETOF_SIZE == OE_OFFSETOF(oe_debug_enclave_t, size));
    OE_TEST(ENCLAVE_SIZEOF_SIZE == OE_SIZEOF(oe_debug_enclave_t, size));

    OE_TEST(
        ENCLAVE_OFFSETOF_TCS_ARRAY ==
        OE_OFFSETOF(oe_debug_enclave_t, tcs_array));
    OE_TEST(
        ENCLAVE_SIZEOF_TCS_ARRAY == OE_SIZEOF(oe_debug_enclave_t, tcs_array));

    OE_TEST(
        ENCLAVE_OFFSETOF_TCS_COUNT ==
        OE_OFFSETOF(oe_debug_enclave_t, tcs_count));
    OE_TEST(
        ENCLAVE_SIZEOF_TCS_COUNT == OE_SIZEOF(oe_debug_enclave_t, tcs_count));

    OE_TEST(ENCLAVE_OFFSETOF_FLAGS == OE_OFFSETOF(oe_debug_enclave_t, flags));
    OE_TEST(ENCLAVE_SIZEOF_FLAGS == OE_SIZEOF(oe_debug_enclave_t, flags));

    OE_TEST(ENCLAVE_MASK_DEBUG == OE_DEBUG_ENCLAVE_MASK_DEBUG);
    OE_TEST(ENCLAVE_MASK_SIMULATE == OE_DEBUG_ENCLAVE_MASK_SIMULATE);

    OE_TEST(
        ENCLAVE_OFFSETOF_MODULES == OE_OFFSETOF(oe_debug_enclave_t, modules));
    OE_TEST(ENCLAVE_SIZEOF_MODULES == OE_SIZEOF(oe_debug_enclave_t, modules));

    /* oe_debug_module_t */
    OE_TEST(MODULE_OFFSETOF_MAGIC == OE_OFFSETOF(oe_debug_module_t, magic));
    OE_TEST(MODULE_SIZEOF_MAGIC == OE_SIZEOF(oe_debug_module_t, magic));
    OE_TEST(MODULE_MAGIC_VALUE == OE_DEBUG_MODULE_MAGIC);

    OE_TEST(MODULE_OFFSETOF_VERSION == OE_OFFSETOF(oe_debug_module_t, version));
    OE_TEST(MODULE_SIZEOF_VERSION == OE_SIZEOF(oe_debug_module_t, version));

    OE_TEST(MODULE_OFFSETOF_NEXT == OE_OFFSETOF(oe_debug_module_t, next));
    OE_TEST(MODULE_SIZEOF_NEXT == OE_SIZEOF(oe_debug_module_t, next));

    OE_TEST(MODULE_OFFSETOF_PATH == OE_OFFSETOF(oe_debug_module_t, path));
    OE_TEST(MODULE_SIZEOF_PATH == OE_SIZEOF(oe_debug_module_t, path));

    OE_TEST(
        MODULE_OFFSETOF_PATH_LENGTH ==
        OE_OFFSETOF(oe_debug_module_t, path_length));
    OE_TEST(
        MODULE_SIZEOF_PATH_LENGTH == OE_SIZEOF(oe_debug_module_t, path_length));

    OE_TEST(
        MODULE_OFFSETOF_BASE_ADDRESS ==
        OE_OFFSETOF(oe_debug_module_t, base_address));
    OE_TEST(
        MODULE_SIZEOF_BASE_ADDRESS ==
        OE_SIZEOF(oe_debug_module_t, base_address));

    OE_TEST(MODULE_OFFSETOF_SIZE == OE_OFFSETOF(oe_debug_module_t, size));
    OE_TEST(MODULE_SIZEOF_SIZE == OE_SIZEOF(oe_debug_module_t, size));

    printf("Debugger contract validated on host side.\n");
}
