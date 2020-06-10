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
#include "switchless_one_tcs_u.h"

#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

static status_e switchless_func_status = FUNC_NOT_START;
void* thread_func(void* arg)
{
    oe_enclave_t* enclave = (oe_enclave_t*)arg;
    oe_result_t ret = enc_empty_switchless(enclave, &switchless_func_status);
    OE_TEST(ret == OE_OK);
    return NULL;
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

    printf("OneTCSTest::test\n");
    printf("Create enclave with Switchless Calls and one TCS only.\n");
    printf("Call empty switchless ecall, it is expected to pass...\n");
    printf("Call empty ecall, it is expected to fail since TCS is occupied by "
           "trusted worker thread...\n");

    const uint32_t flags = oe_get_create_flags();

    oe_enclave_setting_context_switchless_t switchless_setting = {1, 1};
    oe_enclave_setting_t settings[] = {
        {.setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
         .u.context_switchless_setting = &switchless_setting}};

    if ((result = oe_create_switchless_one_tcs_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             settings,
             OE_COUNTOF(settings),
             &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    oe_thread_t tid;
    int ret = 0;
    if ((ret = oe_thread_create(&tid, thread_func, enclave)))
    {
        oe_put_err("thread_create(host): ret=%u", ret);
    }

    volatile status_e* p_switchless_func_status = &switchless_func_status;
    while (*p_switchless_func_status != FUNC_WORKING)
    {
#if defined(__linux__)
        usleep(100);
#elif defined(_WIN32)
        Sleep(0);
#endif
    }

    OE_TEST(enc_empty_regular(enclave) == OE_OUT_OF_THREADS);

    // let enclave function to exit
    *p_switchless_func_status = FUNC_EXIT;

    oe_thread_join(tid);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    printf("=== passed all tests (switchless_one_tcs)\n");

    return 0;
}
