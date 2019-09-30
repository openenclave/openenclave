// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if _MSC_VER
#include <Windows.h>
#endif
#include "../../../host/strings.h"
#include "switchless_u.h"

#define STRING_LEN 100

#if _MSC_VER
static double frequency;
#endif

double get_relative_time_in_microseconds()
{
#if __GNUC__
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    return (double)current_time.tv_sec * 1000000 +
           (double)current_time.tv_nsec / 1000.0;
#elif _MSC_VER
    double current_time;
    QueryPerformanceCounter(&current_time);
    return current_time / frequency;
#endif
}

int host_echo_switchless(char* in, char* out, char* str1, char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, "host string parameter") == 0);
    OE_TEST(strcmp(str2, "host string on stack") == 0);

    strcpy(out, in);

    return 0;
}

int host_echo_regular(char* in, char* out, char* str1, char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, "host string parameter") == 0);
    OE_TEST(strcmp(str2, "host string on stack") == 0);

    strcpy(out, in);

    return 0;
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

#if _MSC_VER
    QueryPerformanceFrequency(&frequency);
    frequency /= 1000000; // convert to microseconds
#endif

    const uint32_t flags = oe_get_create_flags();

    // Enable switchless and configure host worker number
    oe_enclave_setting_context_switchless_t config = {1, 0};
    oe_enclave_config_t configs[] = {{
        .config_type = OE_ENCLAVE_CONFIG_CONTEXT_SWITCHLESS,
        .u.context_switchless_config = &config,
    }};

    if ((result = oe_create_switchless_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             configs,
             OE_COUNTOF(configs),
             &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    char out[STRING_LEN];
    int return_val;

    double switchless_microseconds = 0;
    double start, end;

    // Increase this number to have a meaningful performance measurement
    int repeats = 10;

    start = get_relative_time_in_microseconds();

    OE_TEST(
        enc_echo_switchless(
            enclave, &return_val, "Hello World", out, repeats) == OE_OK);

    end = get_relative_time_in_microseconds();
    switchless_microseconds = end - start;

    double regular_microseconds = 0;
    start = get_relative_time_in_microseconds();

    OE_TEST(
        enc_echo_regular(enclave, &return_val, "Hello World", out, repeats) ==
        OE_OK);

    end = get_relative_time_in_microseconds();
    regular_microseconds = end - start;

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf(
        "Time spent in repeating OCALL %d times: switchless %d vs "
        "regular %d ms, speed up: %.2f\n",
        repeats,
        (int)switchless_microseconds / 1000,
        (int)regular_microseconds / 1000,
        (double)regular_microseconds / switchless_microseconds);
    printf("=== passed all tests (switchless)\n");

    return 0;
}
