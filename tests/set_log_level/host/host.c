// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <openenclave/trace.h>
#include <stdio.h>
#include "set_log_level_a_u.h"
#include "set_log_level_b_u.h"

void log_host_test(const char* log_level_str)
{
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_INFO,
            "Host log_level=%s, message log_level=INFO\n",
            log_level_str) == OE_OK);
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_WARNING,
            "Host log_level=%s, message log_level=WARN\n",
            log_level_str) == OE_OK);
    OE_TEST(
        oe_log(
            OE_LOG_LEVEL_ERROR,
            "Host log_level=%s, message log_level=ERROR\n",
            log_level_str) == OE_OK);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    oe_enclave_t* enclave_without_logging = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if (strstr(argv[1], "enc_a") != NULL)
    {
        fprintf(
            stdout, "Test 1: oe_set_host_log_level before enclave creation\n");

        OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_INFO) == OE_OK);
        log_host_test("INFO");

        OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_WARNING) == OE_OK);
        log_host_test("WARN");

        OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_ERROR) == OE_OK);
        log_host_test("ERROR");

        fprintf(
            stdout,
            "Test 2: oe_set_enclave_log_level before enclave creation : "
            "Expected OE_INVALID_PARAMETER\n");
        OE_TEST(
            oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_INFO) ==
            OE_INVALID_PARAMETER);

        if ((result = oe_create_set_log_level_a_enclave(
                 argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) !=
            OE_OK)
            oe_put_err("oe_create_enclave(): result=%u", result);

        fprintf(
            stdout,
            "Test 3: oe_set_enclave_log_level after enclave creation\n");
        /*
         * For enclave logs to be logged via the host logging (stdout, host
         * callback) method, we need to set both the host and enclave log level.
         * Enclave logs being logged using enclave logging callback (within the
         * enclave) do not need to set host log level.
         */
        OE_TEST(
            oe_set_host_log_level(OE_LOG_LEVEL_WARNING) == OE_OK &&
            oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_WARNING) == OE_OK);
        OE_TEST(enc_test(enclave, "WARN") == OE_OK);

        OE_TEST(
            oe_set_host_log_level(OE_LOG_LEVEL_INFO) == OE_OK &&
            oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_INFO) == OE_OK);
        OE_TEST(enc_test(enclave, "INFO") == OE_OK);

        OE_TEST(
            oe_set_host_log_level(OE_LOG_LEVEL_ERROR) == OE_OK &&
            oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_ERROR) == OE_OK);
        OE_TEST(enc_test(enclave, "ERROR") == OE_OK);

        fprintf(
            stdout,
            "Test 4: Set enclave log level verbosity greater than host log"
            " level verbosity. Expected OE_CONSTRAINT_FAILED\n");
        /* Current host log level = ERROR, set enclave log level to WARN */
        OE_TEST(
            oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_INFO) ==
            OE_CONSTRAINT_FAILED);

        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

#if defined(__linux__)
        /*
         * In Windows, after oe_terminate_enclave calling
         * oe_set_enclave_log_level, which makes an ecall, causes seg fault.
         */
        fprintf(
            stdout,
            "Test 5: oe_set_enclave_log_level after enclave termination. "
            "Expected OE_NOT_FOUNDd\n");
        OE_TEST(
            oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_ERROR) ==
            OE_NOT_FOUND);
#endif
    }
    else
    {
        fprintf(
            stdout,
            "Test 6: oe_set_enclave_log_level on enclave without logging.edl "
            "imported. Expected OE_NOT_FOUND\n");

        if ((result = oe_create_set_log_level_b_enclave(
                 argv[1],
                 OE_ENCLAVE_TYPE_AUTO,
                 flags,
                 NULL,
                 0,
                 &enclave_without_logging)) != OE_OK)
            oe_put_err("oe_create_enclave(): result=%u", result);

        OE_TEST(
            oe_set_enclave_log_level(
                enclave_without_logging, OE_LOG_LEVEL_ERROR) == OE_NOT_FOUND);

        OE_TEST(oe_terminate_enclave(enclave_without_logging) == OE_OK);
    }
    return 0;
}
