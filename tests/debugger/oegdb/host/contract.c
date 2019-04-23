// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/error.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "../../../../host/sgx/enclave.h"

// These values are filled by the debugger.
// The variables are marked volatile so that the compiler does not hard-code
// the initialization value of the variables in comparision.
// Since 0 could be a legal value for some of these items, they are
// initialized to -1.
volatile uint64_t OE_ENCLAVE_MAGIC_FIELD = (uint64_t)-1;
volatile uint64_t OE_ENCLAVE_ADDR_FIELD = (uint64_t)-1;
volatile uint64_t OE_ENCLAVE_HEADER_LENGTH = (uint64_t)-1;
volatile char OE_ENCLAVE_HEADER_FORMAT[10];
volatile uint64_t OE_ENCLAVE_MAGIC_VALUE = (uint64_t)-1;
volatile uint64_t OE_ENCLAVE_FLAGS_OFFSET = (uint64_t)-1;
volatile uint64_t OE_ENCLAVE_FLAGS_LENGTH = (uint64_t)-1;
volatile char OE_ENCLAVE_FLAGS_FORMAT[10];
volatile uint64_t OE_ENCLAVE_THREAD_BINDING_OFFSET = (uint64_t)-1;
volatile uint64_t THREAD_BINDING_SIZE = (uint64_t)-1;
volatile uint64_t THREAD_BINDING_HEADER_LENGTH = (uint64_t)-1;
volatile char THREAD_BINDING_HEADER_FORMAT[10];

void assert_debugger_binary_contract_host_side()
{
    OE_TEST(OE_ENCLAVE_MAGIC_FIELD == OE_OFFSETOF(oe_enclave_t, magic));
    OE_TEST(OE_ENCLAVE_ADDR_FIELD == OE_OFFSETOF(oe_enclave_t, addr));
    OE_TEST(OE_ENCLAVE_HEADER_LENGTH == OE_OFFSETOF(oe_enclave_t, bindings));
    OE_TEST(strcmp((const char*)OE_ENCLAVE_HEADER_FORMAT, "QQQQQ") == 0);
    OE_TEST(OE_ENCLAVE_MAGIC_VALUE == ENCLAVE_MAGIC);
    OE_TEST(OE_ENCLAVE_FLAGS_LENGTH == 2);

    OE_TEST(OE_ENCLAVE_FLAGS_OFFSET == OE_OFFSETOF(oe_enclave_t, debug));
    OE_TEST(strcmp((const char*)OE_ENCLAVE_FLAGS_FORMAT, "BB") == 0);
    OE_TEST(
        OE_ENCLAVE_THREAD_BINDING_OFFSET ==
        OE_OFFSETOF(oe_enclave_t, bindings));

    OE_TEST(THREAD_BINDING_SIZE == sizeof(ThreadBinding));
    OE_TEST(THREAD_BINDING_HEADER_LENGTH == OE_OFFSETOF(ThreadBinding, thread));
    OE_TEST(strcmp((const char*)THREAD_BINDING_HEADER_FORMAT, "Q") == 0);

    printf("Debugger contract validated on host side.\n");
}
