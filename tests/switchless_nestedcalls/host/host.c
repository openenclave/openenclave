// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <inttypes.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../../host/hostthread.h"
#include "../../../host/strings.h"
#include "switchless_nestedcalls_u.h"

// global counters to increment in ocalls
uint32_t ocall1_counter = 0;
uint32_t ocall2_counter = 0;

// global enclave id to use by ocalls
oe_enclave_t* g_enclave = 0;

/**
 * ocall1 - increment counter and ecall2()
 */
void host_ocall1_switchless(void)
{
    ocall1_counter++;
    enc_ecall2_switchless(g_enclave);
}

/**
 * ocall2 - increment counter and return
 */
void host_ocall2_switchless(void)
{
    ocall2_counter++;
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("Run nested switchless Calls ecall->ocall->ecall->ocall.\n");

    const uint32_t flags = oe_get_create_flags();

    oe_enclave_setting_context_switchless_t switchless_setting = {1, 1};
    oe_enclave_setting_t settings[] = {
        {.setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
         .u.context_switchless_setting = &switchless_setting}};

    if ((result = oe_create_switchless_nestedcalls_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             settings,
             OE_COUNTOF(settings),
             &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    g_enclave = enclave;

    result = enc_ecall1_switchless(enclave);
    OE_TEST(result == OE_OK);

    OE_TEST(ocall1_counter == 1);
    OE_TEST(ocall2_counter == 1);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    printf("=== passed all tests (switchless_nestedcalls)\n");

    return 0;
}
