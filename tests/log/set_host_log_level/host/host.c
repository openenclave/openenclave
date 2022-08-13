// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <openenclave/trace.h>
#include <stdio.h>
#include "set_host_log_level_u.h"

void log_host_test(const char* log_level_str)
{
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_INFO,
            "[Host] log_level=%s, message log_level=INFO\n",
            log_level_str) == OE_OK);
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_WARNING,
            "[Host] log_level=%s, message log_level=WARN\n",
            log_level_str) == OE_OK);
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_ERROR,
            "[Host] log_level=%s, message log_level=ERROR\n",
            log_level_str) == OE_OK);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    fprintf(stdout, "Test 1: oe_set_host_log_level before enclave creation\n");

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_INFO) == OE_OK);
    log_host_test("INFO");

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_WARNING) == OE_OK);
    log_host_test("WARN");

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_ERROR) == OE_OK);
    log_host_test("ERROR");

    if ((result = oe_create_set_host_log_level_enclave(
             argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    fprintf(stdout, "Test 2: oe_set_host_log_level After enclave creation\n");

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_INFO) == OE_OK);
    log_host_test("INFO");
    OE_TEST(enc_log_test(enclave, "INFO") == OE_OK);

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_WARNING) == OE_OK);
    log_host_test("WARN");
    OE_TEST(enc_log_test(enclave, "WARN") == OE_OK);

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_ERROR) == OE_OK);
    log_host_test("ERROR");
    OE_TEST(enc_log_test(enclave, "ERROR") == OE_OK);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    fprintf(
        stdout, "Test 3: oe_set_host_log_level After enclave termination\n");

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_INFO) == OE_OK);
    log_host_test("INFO");

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_WARNING) == OE_OK);
    log_host_test("WARN");

    OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_ERROR) == OE_OK);
    log_host_test("ERROR");

    return 0;
}
