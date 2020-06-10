// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if _MSC_VER
#include <windows.h>
#endif
#include "../../../host/hostthread.h"
#include "switchless_threads_u.h"

// For SGX, the enclave supports up to 8 concurrent threads in it. We have
// to reserve one for the main host thread (calling into enc_echo_multiple).
// This leaves us 7 host threads to call into enc_echo_single.
#define NUM_HOST_THREADS 7
#define STRING_LEN 100
#define STRING_HELLO "Hello World"
#define HOST_PARAM_STRING "host string parameter"
#define HOST_STACK_STRING "host string on stack"

int host_echo_switchless(char* in, char* out, char* str1, char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, HOST_PARAM_STRING) == 0);
    OE_TEST(strcmp(str2, HOST_STACK_STRING) == 0);

    strcpy_s(out, STRING_LEN, in);

    return 0;
}

int host_echo_regular(char* in, char* out, char* str1, char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, HOST_PARAM_STRING) == 0);
    OE_TEST(strcmp(str2, HOST_STACK_STRING) == 0);

    strcpy_s(out, STRING_LEN, in);

    return 0;
}

void* thread_func(void* arg)
{
    char out[100];
    int return_val;

    oe_enclave_t* enclave = (oe_enclave_t*)arg;
    oe_result_t result =
        enc_echo_single(enclave, &return_val, "Hello World", out);

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (return_val != 0)
        oe_put_err("ECALL failed args.result=%d", return_val);

    if (strcmp("Hello World", out) != 0)
        oe_put_err("ecall failed: %s != %s\n", "Hello World", out);

    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    // Enable switchless and configure host worker number
    oe_enclave_setting_context_switchless_t switchless_setting = {2, 0};
    oe_enclave_setting_t settings[] = {
        {.setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
         .u.context_switchless_setting = &switchless_setting}};

    if ((result = oe_create_switchless_threads_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             settings,
             OE_COUNTOF(settings),
             &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    oe_thread_t threads[NUM_HOST_THREADS];

    // Start threads that each invokes 'enc_echo_single', an ECALL that makes
    // only one regular OCALL and one switchless OCALL.
    for (int i = 0; i < NUM_HOST_THREADS; i++)
    {
        int ret = 0;
        if ((ret = oe_thread_create(&threads[i], thread_func, enclave)))
        {
            oe_put_err("thread_create(host): ret=%u", ret);
        }
    }

    // Invoke 'enc_echo_multiple` which makes multiple regular OCALLs and
    // multiple switchless OCALLs.
    char out[STRING_LEN];
    int return_val;
    int repeats = 10;
    OE_TEST(
        enc_echo_multiple(enclave, &return_val, "Hello World", out, repeats) ==
        OE_OK);

    // Wait for the threads to complete.
    for (int i = 0; i < NUM_HOST_THREADS; i++)
    {
        oe_thread_join(threads[i]);
    }

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (switchless_threads)\n");

    return 0;
}
