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
#include "switchless_atexit_calls_u.h"

// global enclave id to use by ocalls
oe_enclave_t* g_enclave = 0;

int test1_passed;
int test2_passed;

void host_ocall1_switchless(int value)
{
    if (value == 0x1234)
        test1_passed = 1;
}

void host_ocall2_switchless(void)
{
    int value;

    if (enc_ecall_switchless(g_enclave, &value) != OE_OK)
        goto done;

    if (value != 0x5678)
        goto done;

    test2_passed = 1;

done:
    return;
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

    const uint32_t flags = oe_get_create_flags();

    oe_enclave_setting_context_switchless_t switchless_setting = {1, 1};
    oe_enclave_setting_t settings[] = {
        {.setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
         .u.context_switchless_setting = &switchless_setting}};

    if ((result = oe_create_switchless_atexit_calls_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             settings,
             OE_COUNTOF(settings),
             &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    g_enclave = enclave;

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    /* Test 1: the atexit function makes an OCALL */
    OE_TEST(test1_passed == 1);
    /* Test 2: the atexit function makes an OCALL and a nested ECALL */
    OE_TEST(test2_passed == 1);

    printf("=== passed all tests (switchless_atexit_calls)\n");

    return 0;
}
