// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <openenclave/trace.h>
#include <stdio.h>
#include "set_enclave_log_level_u.h"

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

    fprintf(
        stdout,
        "Test 1: oe_set_enclave_log_level before enclave creation : "
        "Expected OE_INVALID_PARAMETER\n");
    OE_TEST(
        oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_INFO) ==
        OE_INVALID_PARAMETER);

    if ((result = oe_create_set_enclave_log_level_enclave(
             argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    fprintf(
        stdout, "Test 2: oe_set_enclave_log_level after enclave creation\n");
    /*
     * For enclave logs to be logged via the host logging (stdout, host
     * callback) method, we need to set both the host and enclave log level.
     * Enclave logs being logged using enclave logging callback (within the
     * enclave) do not need to set host log level.
     */

    OE_TEST(
        oe_set_host_log_level(OE_LOG_LEVEL_INFO) == OE_OK &&
        oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_INFO) == OE_OK);
    OE_TEST(enc_log_test(enclave, "INFO") == OE_OK);

    OE_TEST(
        oe_set_host_log_level(OE_LOG_LEVEL_WARNING) == OE_OK &&
        oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_WARNING) == OE_OK);
    OE_TEST(enc_log_test(enclave, "WARN") == OE_OK);

    OE_TEST(
        oe_set_host_log_level(OE_LOG_LEVEL_ERROR) == OE_OK &&
        oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_ERROR) == OE_OK);
    OE_TEST(enc_log_test(enclave, "ERROR") == OE_OK);

    fprintf(
        stdout,
        "Test 3: Set enclave log level verbosity greater than host log"
        " level verbosity. Expected OE_CONSTRAINT_FAILED\n");
    /* Current host log level = ERROR, set enclave log level to WARN */
    OE_TEST(
        oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_INFO) ==
        OE_CONSTRAINT_FAILED);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    return 0;
}
